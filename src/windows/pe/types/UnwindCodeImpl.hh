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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/pe/types/UnwindCode.hh>

namespace introvirt {
namespace windows {
namespace pe {

namespace structs {

union _UnwindCode {
    struct {
        uint8_t CodeOffset;
        uint8_t UnwindOp : 4;
        uint8_t OpInfo : 4;
    } __attribute__((ms_struct));
    uint16_t FrameOffset;
};

} // namespace structs

class UnwindCodeImpl final : public UnwindCode {
  public:
    uint8_t CodeOffset() const override { return data_->CodeOffset; }
    UNWIND_OP UnwindOp() const override { return static_cast<UNWIND_OP>(data_->UnwindOp); }
    uint8_t OpInfo() const override { return data_->OpInfo; }
    uint16_t FrameOffset() const override { return data_->FrameOffset; }
    uint8_t CodeCount() const override { return CodeCount_; }
    uint32_t LargeAllocSize() const override { return LargeAllocSize_; }

    UnwindCodeImpl(const GuestVirtualAddress& gva) : data_(gva), CodeCount_(1), LargeAllocSize_(0) {
        switch (data_->UnwindOp) {
        case UNWIND_OP::UWOP_ALLOC_LARGE: {
            ++CodeCount_;

            if (data_->OpInfo != 0u) {
                guest_ptr<uint32_t> next(gva + sizeof(structs::_UnwindCode));
                LargeAllocSize_ = *next;
                ++CodeCount_;
            } else {
                guest_ptr<uint16_t> next(gva + sizeof(structs::_UnwindCode));
                LargeAllocSize_ = *next;
            }
            break;
        }
        case UNWIND_OP::UWOP_SAVE_NONVOL:
        case UNWIND_OP::UWOP_SAVE_XMM128:
        case UNWIND_OP::UWOP_SAVE_XMM:
            ++CodeCount_;
            break;
        case UNWIND_OP::UWOP_SAVE_NONVOL_FAR:
        case UNWIND_OP::UWOP_SAVE_XMM128_FAR:
        case UNWIND_OP::UWOP_SAVE_XMM_FAR:
            CodeCount_ += 2;
            break;
        default:
            break;
        }
    }

  private:
    guest_ptr<structs::_UnwindCode> data_;
    uint32_t CodeCount_;
    uint32_t LargeAllocSize_;
};

} // namespace pe
} // namespace windows
} // namespace introvirt
