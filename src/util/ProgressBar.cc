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

#include <introvirt/util/ProgressBar.hh>

#include <iomanip>

namespace introvirt {

class ProgressBar::IMPL {
  public:
    IMPL(uint16_t ProgressBarSize, std::ostream& stream)
        : stream_(stream), width_(ProgressBarSize) {}

  public:
    std::ostream& stream_;
    const uint32_t width_;
};

ProgressBar::ProgressBar(uint16_t width, std::ostream& stream)
    : pImpl_(std::make_unique<IMPL>(width, stream)) {

    pImpl_->stream_.precision(3);
    pImpl_->stream_.setf(std::ios::fixed);
}

ProgressBar::~ProgressBar() = default;

void ProgressBar::clear() {
    for (size_t i = 0; i < pImpl_->width_ + 11; ++i) {
        pImpl_->stream_ << ' ';
    }
    pImpl_->stream_ << '\r';
}

void ProgressBar::draw(float percentComplete) {
    pImpl_->stream_ << "[";
    if (percentComplete > 0) {
        const float progressBarsCount = pImpl_->width_ / (100.0f / percentComplete);
        for (size_t i = 0; i < pImpl_->width_; ++i) {
            if (i < progressBarsCount) {
                pImpl_->stream_ << '=';
            } else {
                pImpl_->stream_ << ' ';
            }
        }
    }
    pImpl_->stream_ << "] ";
    pImpl_->stream_ << percentComplete;
    pImpl_->stream_ << "%   \r";
    pImpl_->stream_.flush();
}

void ProgressBar::complete() {
    draw(100.0);
    pImpl_->stream_ << std::endl; // Draw a newline and flush
}

} // namespace introvirt