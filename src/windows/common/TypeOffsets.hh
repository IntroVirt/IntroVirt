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

#include "TypeContainer.hh"

#include <introvirt/windows/exception/TypeInformationException.hh>
#include <introvirt/windows/pe.hh>

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>

#include <mspdb/PDB.hh>

#include <algorithm>
#include <cstring>
#include <string>

namespace introvirt {
namespace windows {

template <bool optional, bool recursive, typename LeafType = void>
class MemberTemplate;

enum class TypeID : unsigned int {
    CHILD_LIST,
    CLIENT_ID,
    CM_KEY_BODY,
    CM_KEY_CONTROL_BLOCK,
    CM_KEY_INDEX,
    CM_KEY_NODE,
    CM_KEY_VALUE,
    CM_NAME_CONTROL_BLOCK,
    CMHIVE,
    CONTEXT,
    CONTROL_AREA,
    DEVICE_OBJECT,
    DISPATCHER_HEADER,
    DRIVER_OBJECT,
    DUAL,
    EPROCESS,
    ETHREAD,
    EX_FAST_REF,
    EX_PUSH_LOCK,
    FILE_OBJECT,
    HANDLE_TABLE_ENTRY,
    HANDLE_TABLE_FREE_LIST,
    HANDLE_TABLE,
    HBASE_BLOCK,
    HHIVE,
    HMAP_ENTRY,
    IO_STACK_LOCATION,
    IO_STATUS_BLOCK,
    IRP,
    KAPC_STATE,
    KPCR,
    KPRCB,
    KPROCESS,
    KTHREAD,
    LDR_DATA_TABLE_ENTRY,
    LF_LH_LIST_ENTRY,
    LIST_ENTRY,
    MI_SYSTEM_INFORMATION,
    MM_SESSION_SPACE,
    MMPTE_HARDWARE,
    MMPTE_PROTOTYPE,
    MMPTE_SOFTWARE,
    MMPTE_TRANSITION,
    MMVAD_SHORT,
    MMVAD,
    NT_TIB,
    OBJECT_DIRECTORY_ENTRY,
    OBJECT_DIRECTORY,
    OBJECT_HEADER_CREATOR_INFO,
    OBJECT_HEADER_HANDLE_INFO,
    OBJECT_HEADER_NAME_INFO,
    OBJECT_HEADER_PROCESS_INFO,
    OBJECT_HEADER_QUOTA_INFO,
    OBJECT_HEADER,
    OBJECT_SYMBOLIC_LINK,
    OBJECT_TYPE,
    PEB_LDR_DATA,
    PEB,
    PEB32,
    PORT_MESSAGE,
    PS_PROTECTION,
    RTL_USER_PROCESS_PARAMETERS,
    SECTION_IMAGE_INFORMATION,
    SECTION,
    SECTION_OBJECT,
    SEGMENT,
    SEGMENT_OBJECT,
    SEP_TOKEN_PRIVILEGES,
    SID_AND_ATTRIBUTES,
    SID_IDENTIFIER_AUTHORITY,
    SID,
    SUBSECTION,
    TEB,
    TOKEN,
    UNICODE_STRING,

    TYPE_OFFSET_COUNT
};

template <typename T>
inline const T* LoadOffsets(const TypeContainer& container) {
    return container.typeinfo<T>();
}

class TypeOffsets {
  public:
    TypeOffsets(const TypeContainer& container, const mspdb::PDB& pdb,
                const std::string& structure_name, size_t base_offset)
        : lfStruct_(pdb.find_struct(structure_name)), pointer_size_(container.x64() ? 8 : 4),
          struct_size_(lfStruct_ ? lfStruct_->size() : 0), base_offset_(base_offset) {

        if (unlikely(lfStruct_ == nullptr)) {
            throw TypeInformationException("Could not find type " + structure_name +
                                           " in PDB file");
        }
    }
    ~TypeOffsets() = default;

  public:
    inline uint16_t offset() const { return base_offset_; }
    inline int64_t size() const { return struct_size_; }

  protected:
    const mspdb::LF_FIELDLIST_CONTAINER* const lfStruct_;
    const size_t pointer_size_;
    const int64_t struct_size_;
    const size_t base_offset_;
    friend class MemberTemplate<false, false>;
    friend class MemberTemplate<false, true>;
    friend class MemberTemplate<true, false>;
    friend class MemberTemplate<true, true>;
};

template <bool optional, bool recursive, typename LeafType>
class MemberTemplate final {
  public:
    MemberTemplate(const TypeOffsets& offsets, const std::string& field_name) {
        if (!find_field(offsets, field_name)) {
            if constexpr (!optional)
                throw TypeInformationException("Failed to find field " + field_name);
        }
    }
    MemberTemplate(const TypeOffsets& offsets, const std::vector<std::string>& field_names) {
        for (const auto& field_name : field_names) {
            if (find_field(offsets, field_name)) {
                return;
            }
        }
        if constexpr (!optional)
            throw TypeInformationException("Failed to find field " + field_names.front());
    }
    MemberTemplate& operator=(const MemberTemplate&) = default;

  private:
    bool find_field(const TypeOffsets& offsets, const std::string& field_name) {
        const mspdb::LF_MEMBER* lfMember = nullptr;
        const mspdb::LF_TYPE* lfType = nullptr;

        size_t total_offset = offsets.base_offset_;

        if constexpr (!recursive) {
            // Standard search
            lfMember = offsets.lfStruct_->find_member(field_name);
            if (lfMember) {
                total_offset += lfMember->offset();
                lfType = &(lfMember->index());
            }
        } else {
            // Recursive search
            lfMember = offsets.lfStruct_->find_member_recursive(field_name, total_offset);
            if (lfMember) {
                lfType = &(lfMember->index());
            }
        }

        if (lfType) {
            offset_ = total_offset;
            exists_ = true;

            // Remove LF_MODIFIER types
            while (lfType->type() == mspdb::LEAF_TYPE::LF_MODIFIER) {
                lfType = &(static_cast<const mspdb::LF_MODIFIER*>(lfType)->modified_type());
            }

            leaf_type_ = lfType->type();
            switch (leaf_type_) {
            case mspdb::LEAF_TYPE::LF_ARRAY:
                size_ = static_cast<const mspdb::LF_ARRAY*>(lfType)->size();
                break;
            case mspdb::LEAF_TYPE::LF_BITFIELD: {
                /*
                 *  To get the mask, we do (2^length)-1.
                 *  For example, length 2:
                 *      ((2^2)-1) = 3 = 0b11
                 *  Then we shift it into position.
                 *  For example, position 4:
                 *      0b11 << 4 = 0b110000
                 *  Position 0 is the least significant bit, and would have no shift.
                 */
                const auto* lfBitfield = static_cast<const mspdb::LF_BITFIELD*>(lfType);
                mask_ = (((1ull << lfBitfield->length()) - 1ull) << lfBitfield->position());
                shift_ = lfBitfield->position();

                if (lfBitfield->base_type().type() == mspdb::LEAF_TYPE::LF_BUILTIN) {
                    size_ = static_cast<const mspdb::LF_BUILTIN&>(lfBitfield->base_type()).size();
                }
                break;
            }
            case mspdb::LEAF_TYPE::LF_BUILTIN: {
                const auto* lfBuiltin = static_cast<const mspdb::LF_BUILTIN*>(lfType);
                if (lfBuiltin->pointer()) {
                    leaf_type_ = mspdb::LEAF_TYPE::LF_POINTER;
                    size_ = offsets.pointer_size_;
                } else {
                    size_ = lfBuiltin->size();
                }
                break;
            }
            case mspdb::LEAF_TYPE::LF_POINTER:
                size_ = static_cast<const mspdb::LF_POINTER*>(lfType)->size();
                break;
            default:
                break;
            }
        }

        return exists_;
    }

  public:
    template <typename T>
    inline T get_bitfield(const guest_ptr<const char[]>& buffer) const {
        return get_bitfield<T>(buffer.get());
    }

    template <typename T>
    inline T get_bitfield(const guest_ptr<char[]>& buffer) const {
        return get_bitfield<T>(buffer.get());
    }

    template <typename T>
    inline void set_bitfield(const guest_ptr<char[]>& buffer, T val) const {
        return set_bitfield<T>(buffer.get(), val);
    }

    template <typename T>
    inline T get_bitfield(const char* buffer) const {
        if (likely(leaf_type_ == mspdb::LEAF_TYPE::LF_BITFIELD)) {
            auto val = copy<uint64_t>(buffer);
            val &= mask_;
            val >>= shift_;
            return val;
        }
        throw TypeInformationException("Field is not a bitfield: " + mspdb::to_string(leaf_type_));
    }
    template <typename T>
    inline void set_bitfield(char* buffer, T val) const {
        run_checks<T>();
        if (likely(leaf_type_ == mspdb::LEAF_TYPE::LF_BITFIELD)) {
            T& orig = ref_internal<T>(buffer);
            orig &= ~(mask_);
            orig |= (val << shift_);
            return;
        }
        throw TypeInformationException("Field is not a bitfield: " + mspdb::to_string(leaf_type_));
    }

    template <typename T>
    inline T& ref(char* buffer) const {
        run_checks<T>();
        if (likely(leaf_type_ != mspdb::LEAF_TYPE::LF_BITFIELD))
            return ref_internal<T>(buffer);

        throw TypeInformationException("Field is a bitfield");
    }
    template <typename T>
    inline const T& ref(const char* buffer) const {
        run_checks<T>();
        if (likely(leaf_type_ != mspdb::LEAF_TYPE::LF_BITFIELD))
            return ref_internal<T>(buffer);

        throw TypeInformationException("Field is a bitfield");
    }

    template <typename T>
    inline const T get(const guest_ptr<const char[]>& buffer) const {
        return get<T>(buffer.get());
    }

    template <typename T>
    inline const T get(const guest_ptr<char[]>& buffer) const {
        return get<T>(buffer.get());
    }

    template <typename T>
    inline void set(const guest_ptr<char[]>& buffer, T val) const {
        set<T>(buffer.get(), val);
    }

    template <typename T>
    inline const T get(const char* buffer) const {
        check_exists();
        if (leaf_type_ != mspdb::LEAF_TYPE::LF_BITFIELD) {
            check_size<T>();
            return ref_internal<T>(buffer);
        } else {
            return get_bitfield<T>(buffer);
        }
    }
    template <typename T>
    inline void set(char* buffer, T val) const {
        run_checks<T>();
        if (leaf_type_ != mspdb::LEAF_TYPE::LF_BITFIELD)
            ref_internal<T>(buffer) = val;
        else
            set_bitfield<T>(buffer, val);
    }

    inline std::string get_string(const guest_ptr<const char[]>& buffer) const {
        return get_string(buffer.get());
    }
    inline std::string get_string(const guest_ptr<char[]>& buffer) const {
        return get_string(buffer.get());
    }
    inline void set_string(const guest_ptr<char[]>& buffer, const std::string& str) const {
        set_string(buffer.get(), str);
    }

    inline std::string get_string(const char* buffer) const {
        check_exists();
        if (likely(leaf_type_ == mspdb::LEAF_TYPE::LF_ARRAY)) {
            const char* array = buffer + offset_;
            return std::string(array, strnlen(array, size_));
        }
        throw TypeInformationException("Field is a bitfield");
    }
    inline void set_string(char* buffer, const std::string& str) const {
        check_exists();

        if (likely(leaf_type_ == mspdb::LEAF_TYPE::LF_ARRAY)) {
            char* array = buffer + offset_;
            std::strncpy(array, str.c_str(), size_);
            std::memset(array + str.size(), 0, size_ - str.size());
        }
        throw TypeInformationException("Field is a bitfield");
    }

    inline operator size_t() const {
        check_exists();
        return offset_;
    }
    inline bool exists() const {
        if constexpr (optional) {
            return exists_;
        } else {
            return true;
        }
    }
    inline uint16_t size() const {
        check_exists();
        return size_;
    }
    inline uint16_t offset() const {
        check_exists();
        return offset_;
    }
    inline uint64_t mask() const {
        check_exists();
        if (likely(leaf_type_ == mspdb::LEAF_TYPE::LF_BITFIELD))
            return mask_;
        throw TypeInformationException("Not a bitfield");
    }
    inline uint64_t shift() const {
        check_exists();
        if (likely(leaf_type_ == mspdb::LEAF_TYPE::LF_BITFIELD))
            return shift_;
        throw TypeInformationException("Not a bitfield");
    }

  private:
    template <typename T>
    inline void run_checks() const {
        check_exists();
        check_size<T>();
    }

    template <typename T>
    inline void check_size() const {
        if (unlikely(size_ != 0 && sizeof(T) > size_)) {
            throw TypeInformationException("Type is too large for size");
        }
    }

    inline void check_exists() const {
        if constexpr (!optional) {
            if (unlikely(!exists())) {
                throw TypeInformationException("Field does not exist");
            }
        }
    }

    template <typename T>
    inline T& ref_internal(char* buffer) const {
        return *reinterpret_cast<T*>(buffer + offset_);
    }

    template <typename T>
    inline const T& ref_internal(const char* buffer) const {
        return *reinterpret_cast<const T*>(buffer + offset_);
    }

    template <typename T>
    inline T copy(const char* buffer) const {
        T result = 0;
        std::memcpy(&result, buffer + offset_, std::min(size_, sizeof(T)));
        return result;
    }

  private:
    size_t offset_{0};
    size_t size_{0};
    uint64_t mask_{0};
    uint64_t shift_{0};
    mspdb::LEAF_TYPE leaf_type_;
    bool exists_{false};
};

using Member = MemberTemplate<false, false>;
using OptionalMember = MemberTemplate<true, false, void>;
using RecursiveMember = MemberTemplate<false, true, void>;
using OptionalRecursiveMember = MemberTemplate<true, true, void>;

#define MEMBER(Name)                                                                               \
    Member Name { *this, #Name }
#define OPTIONAL_MEMBER(Name)                                                                      \
    OptionalMember Name { *this, #Name }
#define RECURSIVE_MEMBER(Name)                                                                     \
    RecursiveMember Name { *this, #Name }
#define OPTIONAL_RECURSIVE_MEMBER(Name)                                                            \
    OptionalRecursiveMember Name { *this, #Name }

#define MEMBER_MULTISZ(Name, ...)                                                                  \
    Member Name {                                                                                  \
        *this, std::vector<std::string> { __VA_ARGS__ }                                            \
    }
#define OPTIONAL_MEMBER_MULTISZ(Name, ...)                                                         \
    OptionalMember Name {                                                                          \
        *this, std::vector<std::string> { __VA_ARGS__ }                                            \
    }
#define RECURSIVE_MEMBER_MULTISZ(Name, ...)                                                        \
    RecursiveMember Name {                                                                         \
        *this, std::vector<std::string> { __VA_ARGS__ }                                            \
    }
#define OPTIONAL_RECURSIVE_MEMBER_MULTISZ(Name, ...)                                               \
    OptionalRecursiveMember Name {                                                                 \
        *this, std::vector<std::string> { __VA_ARGS__ }                                            \
    }

} /* namespace windows */
} /* namespace introvirt */
