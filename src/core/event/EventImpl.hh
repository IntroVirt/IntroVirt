/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include "ControlRegisterEventImpl.hh"
#include "ExceptionEventImpl.hh"
#include "HypervisorEvent.hh"
#include "MemAccessEventImpl.hh"
#include "core/domain/DomainImpl.hh"
#include "core/domain/VcpuImpl.hh"

#include <introvirt/core/event/Event.hh>
#include <introvirt/core/exception/InterruptedException.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>

namespace introvirt {

enum class WakeAction {
    DROP,  // Drop the event
    PASS,  // Let the event go through the normal channels
    ACCEPT // Accept the event, remove the event from the suspended thread map
};

class EventImpl {
  public:
    /**
     * @brief Suspend the event until another event comes in for the same thread
     */
    virtual std::unique_ptr<Event> suspend(std::function<WakeAction(Event&)> check_wakeup) = 0;

    /**
     * @brief Wake the event back up
     */
    virtual WakeAction wake(std::unique_ptr<Event>&& event) = 0;

    /**
     * @brief Execute one instruction in the guest
     *
     * @return std::unique_ptr<Event>
     */
    virtual std::unique_ptr<Event> step() = 0;

    /**
     * @brief Callback for the event poller to resume a stepping event
     *
     * @param event
     */
    virtual void wake_step(std::unique_ptr<Event>&& event) = 0;

    virtual void interrupt() = 0;

    virtual void discard(bool value) = 0;

    virtual bool injection_performed() const = 0;
    virtual void injection_performed(bool value) = 0;

    /**
     * @brief Get a unique identifer for the current thread
     *
     * @return uint64_t
     */
    virtual uint64_t thread_id() const = 0;

    virtual const HypervisorEvent& hypervisor_event() const = 0;
    virtual HypervisorEvent& hypervisor_event() = 0;

    virtual std::unique_ptr<HypervisorEvent> release() = 0;

    virtual uint64_t page_directory() const = 0;
};

/**
 * @brief Base class for events that are passed to libintrovirt API users
 *
 * @tparam _BaseClass The base class to inherit from (.i.e. )
 */
template <typename _BaseClass>
class EventImplTpl : public _BaseClass, public EventImpl {
  public:
    Vcpu& vcpu() final { return hypervisor_event_->vcpu(); }
    const Vcpu& vcpu() const final { return hypervisor_event_->vcpu(); }

    Domain& domain() final { return hypervisor_event_->domain(); }
    const Domain& domain() const final { return hypervisor_event_->domain(); }

    EventType type() const final { return hypervisor_event_->type(); }

    ControlRegisterEvent& cr() override {
        if (unlikely(!cr_))
            throw InvalidMethodException();
        return *cr_;
    }
    const ControlRegisterEvent& cr() const override {
        if (unlikely(!cr_))
            throw InvalidMethodException();
        return *cr_;
    }

    MsrAccessEvent& msr() override { throw InvalidMethodException(); }
    const MsrAccessEvent& msr() const override { throw InvalidMethodException(); }

    ExceptionEvent& exception() override {
        if (unlikely(!exception_))
            throw InvalidMethodException();
        return *exception_;
    }
    const ExceptionEvent& exception() const override {
        if (unlikely(!exception_))
            throw InvalidMethodException();
        return *exception_;
    }

    MemAccessEvent& mem_access() override {
        if (unlikely(!mem_access_))
            throw InvalidMethodException();
        return *mem_access_;
    }
    const MemAccessEvent& mem_access() const override {
        if (unlikely(!mem_access_))
            throw InvalidMethodException();
        return *mem_access_;
    }

    OS os_type() const override { return OS::Unknown; }

    Json::Value json() const override {
        Json::Value result;
        Json::Value event;

        event["type"] = to_string(type());
        event["domain"] = domain().name();
        event["vcpu"] = vcpu().id();

        Json::Value task_json;
        task_json["pid"] = this->task().pid();
        task_json["tid"] = this->task().tid();
        task_json["process_name"] = this->task().process_name();
        event["task"] = std::move(task_json);

        switch (type()) {
        case EventType::EVENT_FAST_SYSCALL:
        case EventType::EVENT_FAST_SYSCALL_RET: {
            if (likely(this->syscall().handler() != nullptr)) {
                event["syscall"] = this->syscall().handler()->json();
            } else {
                Json::Value syscall_json;
                syscall_json["name"] = this->syscall().name();
                event["syscall"] = std::move(syscall_json);
            }
            break;
        }
        case EventType::EVENT_CR_READ:
        case EventType::EVENT_CR_WRITE: {
            Json::Value cr_json;
            cr_json["index"] = cr().index();
            cr_json["value"] = cr().value();
            event["cr"] = std::move(cr_json);
        }
        default:
            break;
        }

        result["event"] = std::move(event);
        return result;
    }

    uint64_t page_directory() const override { return vcpu().registers().cr3(); }

    EventImpl& impl() final { return *this; }

    /**
     * @brief Suspend the event until another event comes in for the same thread
     */
    std::unique_ptr<Event> suspend(std::function<WakeAction(Event&)> check_wakeup) override {
        assert(check_wakeup != nullptr);

        std::unique_lock lock(mtx_);
        hypervisor_event_->domain().suspend_event(*this);

        if (unlikely(interrupted_)) {
            throw InterruptedException();
        }

        auto& vcpu = static_cast<VcpuImpl&>(this->vcpu());

        woke_ = false;
        check_wakeup_ = check_wakeup;

        // Let the VCPU know that it's no longer in an event
        vcpu.complete_event();
        cv_.wait(lock, [this] { return woke_ || interrupted_; });

        if (unlikely(interrupted_)) {
            discard(true);
            throw InterruptedException();
        }

        return std::move(step_event_);
    }

    /**
     * @brief Wake the event back up
     */
    WakeAction wake(std::unique_ptr<Event>&& event) override {
        assert(check_wakeup_ != nullptr);

        WakeAction result = check_wakeup_(*event);
        if (result == WakeAction::ACCEPT) {
            std::unique_lock lock(mtx_);
            check_wakeup_ = std::function<WakeAction(Event&)>();
            woke_ = true;
            step_event_ = std::move(event);
            step_event_->impl().discard(true);
            cv_.notify_all();
        }

        return result;
    }

    /**
     * @brief Execute one instruction in the guest
     *
     * @return std::unique_ptr<Event>
     */
    std::unique_ptr<Event> step() override {
        std::unique_lock lock(mtx_);
        hypervisor_event_->domain().suspend_event_step(*this);

        auto& vcpu = static_cast<VcpuImpl&>(this->vcpu());

        // Turn on single stepping
        const bool original_state = vcpu.single_step();
        vcpu.single_step(true);

        // Resume the VCPU
        woke_ = false;

        vcpu.complete_event();

        // Wait for the single step event
        cv_.wait(lock, [this] { return woke_ || interrupted_; });

        if (unlikely(interrupted_)) {
            discard(true);
            throw InterruptedException();
        }

        // Restore single stepping
        vcpu.single_step(original_state);

        return std::move(step_event_);
    }

    /**
     * @brief Callback for the event poller to resume a stepping event
     *
     * @param event
     */
    void wake_step(std::unique_ptr<Event>&& event) override {
        std::unique_lock lock(mtx_);
        woke_ = true;
        step_event_ = std::move(event);
        cv_.notify_all();
    }

    void interrupt() override {
        std::unique_lock lock(mtx_);
        interrupted_ = true;
        cv_.notify_all();
    }

    void discard(bool value) override { hypervisor_event_->discard(value); }

    /**
     * @brief Get the hypervisor event backing this event
     */
    const HypervisorEvent& hypervisor_event() const override { return *hypervisor_event_; }

    HypervisorEvent& hypervisor_event() override { return *hypervisor_event_; }

    std::unique_ptr<HypervisorEvent> release() override { return std::move(hypervisor_event_); }

    virtual bool injection_performed() const override { return injection_performed_; }
    virtual void injection_performed(bool value) override { injection_performed_ = value; }

    uint64_t id() const override { return hypervisor_event_->id(); }

    EventImplTpl(std::unique_ptr<HypervisorEvent>&& hypervisor_event)
        : hypervisor_event_(std::move(hypervisor_event)) {

        switch (type()) {
        case EventType::EVENT_CR_READ:
        case EventType::EVENT_CR_WRITE:
            cr_.emplace(*hypervisor_event_);
            break;
        case EventType::EVENT_EXCEPTION:
            exception_.emplace(*hypervisor_event_);
        case EventType::EVENT_MEM_ACCESS:
            mem_access_.emplace(*hypervisor_event_);
            break;
        }
    }

  protected:
    std::unique_ptr<HypervisorEvent> hypervisor_event_;
    std::optional<ControlRegisterEventImpl> cr_;
    std::optional<ExceptionEventImpl> exception_;
    std::optional<MemAccessEventImpl> mem_access_;

  private:
    // Injection related
    std::mutex mtx_;
    std::condition_variable cv_;
    std::function<WakeAction(Event&)> check_wakeup_;
    std::unique_ptr<Event> step_event_;
    bool injection_performed_ = false;
    bool woke_ = false;
    bool interrupted_ = false;
};

} // namespace introvirt
