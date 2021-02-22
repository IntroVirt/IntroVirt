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

#include <cstdint>
#include <iostream>
#include <memory>

namespace introvirt {

/**
 * @brief Class for displaying a progress bar
 */
class ProgressBar final {
  public:
    /**
     * @brief Redraw the progress bar with the specified percent complete
     *
     * @param percentComplete
     */
    void draw(float percentComplete);

    /**
     * @brief Clear the progress bar line
     */
    void clear();

    /**
     * @brief Set the progress bar to 100%
     *
     */
    void complete();

    /**
     * @brief Construct a new ProgressBar
     *
     * @param width The number of characters wide to make the bar
     * @param stream The stream to write to
     */
    ProgressBar(uint16_t width = 50, std::ostream& stream = std::cout);
    ~ProgressBar();

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
};

} // namespace introvirt