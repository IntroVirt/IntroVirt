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
/* This file is automatically generated. Do not edit. */
#pragma once

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/libraries/WindowsFunctionCall.hh>
{%- for include in includes %}
#include {{ include }}
{%- endfor %}
#include <cstdint>
#include <string>
#include <ostream>
{% for namespace in namespaces %}
namespace {{ namespace }} {
{%- endfor %}

/**
 * @brief Handler for {{ library_name }}!{{ function_name }}
 *
 * @see {{ doc_url }}
 */
class {{ function_name }} final : public WindowsFunctionCall {
  public:
    {% for arg in arguments -%}

    {% for method in arg.get("methods", []) -%}
    {{ method.get("result_type", "void") }} {{ method.get("name", "!!MISSING NAME!!") }}(
      {%- for method_arg in method.get("arguments", []) %}
      {{ method_arg["type"]}} {{ method_arg["name"]}}
      {{ "," if not loop.last }}
      {%- endfor -%}
    ) {{ "const" if method.get("const") }};
    {% endfor %}

    {% endfor %}

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;
    Json::Value json() const override;

    {% if result["type"] != "void" %}
    {% for method in result.get("methods", []) -%}
    {{ method.get("result_type", "void") }} {{ method.get("name", "!!MISSING NAME!!") }}(
      {%- for method_arg in method.get("arguments", []) %}
      {{ method_arg["type"]}} {{ method_arg["name"]}}
      {{ "," if not loop.last }}
      {%- endfor -%}
    ) {{ "const" if method.get("const") }};
    {% endfor %}
    {% endif %}

    {{ function_name }}(Event& event);
    ~{{ function_name }}() override;

   /* Injection helper */
    static 
    {% if result["type"] != "void" -%}
    {{ result["injection"]["result_type"] }}
    {%- else -%}
    void
    {%- endif %}
    inject(
    {%- for arg in arguments -%}
    {{ arg.get("injection", {}).get("type") }} {{ arg.get("injection", {}).get("name") }}
    {{ "," if not loop.last }}
    {%- endfor -%}
    );

    static constexpr int ArgumentCount = {{ arguments|length }};
    inline static const std::string LibraryName = "{{ library_name }}";
    inline static const std::string FunctionName = "{{ function_name }}";
  private:
   /* Injection constructor */
    {{ function_name }}(Event& event,
    {%- for arg in arguments -%}
    {{ arg.get("injection", {}).get("type") }} {{ arg.get("injection", {}).get("name") }}
    {{ "," if not loop.last }}
    {%- endfor -%}
    );

  private:
    {%- for arg in arguments %}
    {%- for variable in arg.get("variables", []) %}
    {{ "mutable" if variable.get("mutable") }} {{ variable.get("type", "MISSING TYPE") }} {{ variable.get("name", "MISSING NAME") }};
    {%- endfor %}
    {%- endfor %}
    {% if result["type"] != "void" or result.get("pointer") -%}
    {%- for variable in result.get("variables", []) %}
    {%- if not variable.get("skip_if_result") %}
    {{ "mutable" if variable.get("mutable") }} {{ variable.get("type", "MISSING TYPE") }} {{ variable.get("name", "MISSING NAME") }};
    {%- endif -%}
    {%- endfor %}
    {% endif %}
};

{% for i in range(namespaces|length - 1, -1, -1) -%}
{% set namespace = namespaces[i] %}
} // namespace {{ namespace }}
{%- endfor %}