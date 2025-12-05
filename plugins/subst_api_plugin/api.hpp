#pragma once

#include "subst_plugin.hpp"


#define CALL_WITH_400(api_name, api_handle, api_namespace, call_name, http_response_code, params_type) \
{std::string("/v1/" #api_name "/" #call_name), \
   api_category::subst_api, \
   [api_handle](string&&, string&& body, url_response_callback&& cb) mutable { \
          auto deadline = api_handle.start(); \
          try { \
             auto params = parse_params<api_namespace::call_name ## _params, params_type>(body);\
             fc::variant result( api_handle.call_name( std::move(params), deadline ) ); \
             cb(http_response_code, std::move(result)); \
          } catch (...) { \
             http_plugin::handle_exception(#api_name, #call_name, body, cb); \
          } \
       }}

#define SUBST_CALL(call_name, http_response_code, params_type) \
    CALL_WITH_400(subst, subst_api, eosio::subst_apis, call_name, http_response_code, params_type)

namespace eosio {

    using eosio::substitution_context;

    class subst_apis {
        const fc::microseconds max_response_time;
        substitution_context& sctx;

        public:
            subst_apis(
                const fc::microseconds& _max_response_time,
                substitution_context& subst_context
            ) :
                max_response_time(_max_response_time),
                sctx(subst_context)
            {}

            void validate() const {}

            fc::time_point start() const {
                validate();
                return fc::time_point::now() + max_response_time;
            }

#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
            struct status_code_descriptor {
                uint8_t codegen_version;
                size_t code_begin;
                unsigned apply_offset;
                int starting_memory_pages;
                size_t initdata_begin;
                unsigned initdata_size;
                unsigned initdata_prologue_size;
            };
            struct status_eosvmoc_cache {
                digest_type code_hash;
                uint8_t vm_version;

                std::string status;
                std::optional<fc::variant> descriptor;
            };
#endif

            struct status_codeobj {
                digest_type code_hash;
                digest_type actual_code_hash;
                std::size_t code_size;
                uint64_t    code_ref_count;
                uint32_t    first_block_used;
                uint8_t     vm_type = 0;
                uint8_t     vm_version = 0;
            };

            struct status_acc_meta_obj {
                uint64_t          recv_sequence;
                uint64_t          auth_sequence;
                uint64_t          code_sequence;
                uint64_t          abi_sequence;
                digest_type       code_hash;
                chain::time_point last_code_update;
                uint32_t          flags;
                uint8_t           vm_type;
                uint8_t           vm_version;
            };

            struct status_result {
                name account;
                uint64_t from_block;
                bool must_activate;

                fc::sha256 original_hash;
                fc::sha256 substitution_hash;

                std::optional<fc::variant> account_metadata_object;
                std::optional<fc::variant> code_object;
                std::optional<fc::variant> eosvmoc_cache_status;
            };

            struct status_results {
                std::vector<fc::variant> rows;
            };

            status_result get_account_status(const name& account) const {
                const auto& meta = sctx.get_by_account(account);

                std::optional<fc::variant> account_meta;
                std::optional<fc::variant> code_object;
                std::optional<fc::variant> vmoc_cache_status;
                status_result result {
                    meta->account,
                    meta->from_block,
                    meta->must_activate,

                    meta->og_hash(),
                    meta->s_hash(),

                    account_meta,
                    code_object,
                    vmoc_cache_status
                };

                const auto& acc_meta = sctx.get_account_metadata_object(account, false);

                // no contract deployed on chain yet
                if (!acc_meta) return result;

                const auto& code_obj = sctx.get_codeobj(account);

#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
                // if oc mode is enabled fetch code descriptor
                std::unique_ptr<eosvmoc_tier>& eosvmoc = sctx.get_eosvmoc();
                if (eosvmoc && meta->og_hash() != digest_type()) {
                    status_eosvmoc_cache ocvm_status;

                    chain::eosvmoc::code_cache_base::get_cd_failure failure = chain::eosvmoc::code_cache_base::get_cd_failure::temporary;
                    const code_descriptor* cd = eosvmoc->cc.get_descriptor_for_code(
                        false,
                        code_obj->code_hash,
                        code_obj->vm_version,
                        false,
                        failure
                    );

                    ocvm_status.code_hash = code_obj->code_hash;
                    ocvm_status.vm_version = code_obj->vm_version;

                    if (cd) {
                        status_code_descriptor occache {
                            cd->codegen_version,
                            cd->code_begin,
                            cd->apply_offset,
                            cd->starting_memory_pages,
                            cd->initdata_begin,
                            cd->initdata_size,
                            cd->initdata_prologue_size
                        };
                        fc::variant vmoc_desc;
                        fc::to_variant(occache, vmoc_desc);
                        ocvm_status.descriptor = vmoc_desc;

                        ocvm_status.status = std::string("ready");

                    } else {
                        if (failure == chain::eosvmoc::code_cache_base::get_cd_failure::temporary)
                            ocvm_status.status = std::string("temporary failure");

                        else
                            ocvm_status.status = std::string("permanent failure");
                    }

                    vmoc_cache_status = ocvm_status;
                }
#endif

                status_codeobj cobj {
                    code_obj->code_hash,
                    sctx.get_codeobj_hash(account),
                    code_obj->code.size(),
                    code_obj->code_ref_count,
                    code_obj->first_block_used,
                    code_obj->vm_type,
                    code_obj->vm_version
                };
                fc::variant cobj_var;
                fc::to_variant(cobj, cobj_var);
                result.code_object = cobj_var;

                status_acc_meta_obj ameta {
                    acc_meta->recv_sequence,
                    acc_meta->auth_sequence,
                    acc_meta->code_sequence,
                    acc_meta->abi_sequence,
                    acc_meta->code_hash,
                    acc_meta->last_code_update,
                    acc_meta->flags,
                    acc_meta->vm_type,
                    acc_meta->vm_version
                };
                fc::variant acc_meta_var;
                fc::to_variant(ameta, acc_meta_var);
                result.account_metadata_object = acc_meta_var;

                return result;
            }


            struct optional_account_param {
                std::optional<name> account;
            };

            // read only

            using status_params = optional_account_param;

            status_results status(const status_params& params, const fc::time_point& deadline) const {
                status_results results;

                if (params.account)
                    results.rows.emplace_back(get_account_status(*params.account));

                else
                    for (const name& account : sctx.get_substitutions())
                        results.rows.emplace_back(get_account_status(account));

                return results;
            }

            // read-write

            struct upsert_params {
                name account;
                uint32_t from_block;
                chain::blob code;
                bool must_activate;
            };

            status_result upsert(const upsert_params& params, const fc::time_point& deadline) {
                std::vector<uint8_t> code(params.code.data.begin(), params.code.data.end());
                sctx.upsert(
                    params.account, params.from_block, code, params.must_activate);
                return get_account_status(params.account);
            }

            using activate_params = optional_account_param;

            status_results activate(const activate_params& params, const fc::time_point& deadline) {
                status_results results;

                if (params.account) {
                    sctx.activate(*params.account);
                    results.rows.emplace_back(get_account_status(*params.account));

                } else
                    for (const name& account : sctx.get_substitutions()) {
                        sctx.activate(account);
                        results.rows.emplace_back(get_account_status(account));
                    }

                return results;
            }

            using deactivate_params = optional_account_param;

            status_results deactivate(const deactivate_params& params, const fc::time_point& deadline) {
                status_results results;

                if (params.account) {
                    sctx.deactivate(*params.account);
                    results.rows.emplace_back(get_account_status(*params.account));

                } else
                    for (const name& account : sctx.get_substitutions()) {
                        sctx.deactivate(account);
                        results.rows.emplace_back(get_account_status(account));
                    }

                return results;
            }

            using remove_params = optional_account_param;

            status_results remove(const remove_params& params, const fc::time_point& deadline) {
                status_results results;

                if (params.account)
                    sctx.remove(*params.account);

                else
                    for (const name& account : sctx.get_substitutions())
                        sctx.remove(account);

                for (const name& account : sctx.get_substitutions())
                    results.rows.emplace_back(get_account_status(account));

                return results;
            }

            using fetch_manifest_params = chain_apis::empty;

            status_results fetch_manifest(const fetch_manifest_params& params, const fc::time_point& deadline) {
                status_results results;

                sctx.fetch_manifest(fc::seconds(DEFAULT_MANIFEST_TIMEOUT));

                for (const name& account : sctx.get_substitutions())
                    results.rows.emplace_back(get_account_status(account));

                return results;
            }
    };

}  // namespace eosio

FC_REFLECT(
    eosio::subst_apis::status_result,
    (account)(from_block)(must_activate)
    (original_hash)(substitution_hash)
    (account_metadata_object)
    (code_object)
    (eosvmoc_cache_status)
)
FC_REFLECT(
    eosio::subst_apis::status_results,
    (rows)
)
FC_REFLECT(
    eosio::subst_apis::status_acc_meta_obj,
    (recv_sequence)
    (auth_sequence)
    (code_sequence)
    (abi_sequence)
    (code_hash)
    (last_code_update)
    (flags)
    (vm_type)
    (vm_version)
)
FC_REFLECT(
    eosio::subst_apis::status_codeobj,
    (code_hash)
    (actual_code_hash)
    (code_size)
    (code_ref_count)
    (first_block_used)
    (vm_type)
    (vm_version)
)

#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
FC_REFLECT(
    eosio::subst_apis::status_code_descriptor,
    (codegen_version)
    (code_begin)
    (apply_offset)
    (starting_memory_pages)
    (initdata_begin)
    (initdata_size)
    (initdata_prologue_size)
)
FC_REFLECT(
    eosio::subst_apis::status_eosvmoc_cache,
    (code_hash)
    (vm_version)
    (status)
    (descriptor)
)
#endif

FC_REFLECT(
    eosio::subst_apis::optional_account_param,
    (account)
)

FC_REFLECT(
    eosio::subst_apis::upsert_params,
    (account)(from_block)(code)
)
