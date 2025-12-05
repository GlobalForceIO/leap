#include "subst_plugin.hpp"

namespace eosio {

    static auto _subst_plugin = application::register_plugin<subst_plugin>();

    class subst_plugin_impl : public std::enable_shared_from_this<subst_plugin_impl> {
        private:
            boost::asio::steady_timer manifest_timer;

        public:
            subst_plugin_impl(boost::asio::io_service& io)
            : manifest_timer(io)
            {}

        substitution_context* subst_ctx;
        chainbase::database* db;
        controller* control;

        appbase::variables_map app_options;

        bool override_tx_time = false;
        bool should_perform_override = false;
        uint32_t override_time = DEFAULT_OVERRIDE_TIME;
        uint32_t manifest_interval = DEFAULT_MANIFEST_INTERVAL;
        uint32_t manifest_timeout = DEFAULT_MANIFEST_TIMEOUT;

        void init(chain_plugin* chain, const variables_map& options) {
            app_options = options;

            control = &chain->chain();
            db = &control->mutable_db();
            subst_ctx = new substitution_context(control);

            manifest_interval = app_options.at("subst-manifest-interval").as<uint32_t>();
            manifest_timeout = app_options.at("subst-manifest-timeout").as<uint32_t>();

            control->get_wasm_interface().substitute_apply = [&](
                const chain::digest_type& code_hash,
                uint8_t vm_type, uint8_t vm_version,
                chain::apply_context& context
            ) {
                try {
                    name receiver = context.get_receiver();
                    auto act = context.get_action();

                    // gpo override hook
                    if (override_tx_time) {
                        if (should_perform_override) pwn_gpo();

                        if (receiver == name("eosio") &&
                            act.name == name("setparams")) {

                            should_perform_override = true;
                            ilog(
                                "setparams detected at ${bnum}, pwning gpo on next action",
                                ("bnum", control->pending_block_num())
                            );
                        }
                    }

                    // substitution hook
                    subst_ctx->apply_hook(code_hash, vm_type, vm_version, context);

                    return false;
                } FC_LOG_AND_RETHROW()
            };

            control->post_db_init = [&]() {
                post_db_init();
            };

            ilog("installed substitution hook for ${cid}", ("cid", control->get_chain_id()));
        }

        void post_db_init(){
            db->add_index<subst_meta_index>();

            override_tx_time = (app_options.count("override-max-tx-time") &&
                                        app_options["override-max-tx-time"].as<uint32_t>());

            should_perform_override = override_tx_time;

            if (should_perform_override) {
                override_time = app_options["override-max-tx-time"].as<uint32_t>();

                ilog("should_perform_override: ${over}ms", ("over",override_time));
            }

            if (app_options.count("subst-by-name")) {
                auto substs = app_options.at("subst-by-name").as<vector<string>>();
                for (auto& s : substs) {
                    std::vector<std::string> v;
                    boost::split(v, s, boost::is_any_of(":"));

                    EOS_ASSERT(
                        v.size() == 2,
                        fc::invalid_arg_exception,
                        "Invalid value ${s} for --subst-by-name"
                        " format is ${account_name}:${path_to_wasm}", ("s", s)
                    );

                    auto sinfo = v[0];
                    auto new_code_path = v[1];

                    std::vector<uint8_t> new_code = eosio::vm::read_wasm(new_code_path);
                    subst_ctx->upsert(sinfo, new_code);
                }
            }
            string manifest_str = app_options.at("subst-manifest").as<string>();
            if (manifest_str != "") {
                fc::url manifest_url = fc::url(manifest_str);
                EOS_ASSERT(
                    manifest_url.proto() == "http",
                    fc::invalid_arg_exception,
                    "Only http protocol supported for now."
                );
                subst_ctx->manifest_url = manifest_url;
                subst_ctx->fetch_manifest(fc::seconds(manifest_timeout));
                schedule_manifest_update();
            }

            subst_ctx->debug_print();
        }

        void schedule_manifest_update() {
            ilog("scheduling manifest update in ${i}", ("i",manifest_interval));
            manifest_timer.expires_from_now(std::chrono::seconds(manifest_interval));
            manifest_timer.async_wait(
                app().executor().wrap(
                    priority::high,
                    exec_queue::read_write,
                    [weak_this = weak_from_this()]( const boost::system::error_code& ec ) {
                        auto self = weak_this.lock();
                        if(self && ec != boost::asio::error::operation_aborted) {
                            ilog("trigger manifest update");
                            try {
                                 self->subst_ctx->fetch_manifest(fc::seconds(self->manifest_timeout));
                            } FC_LOG_AND_DROP();
                            self->schedule_manifest_update();
                        }
                    }
                )
            );
        }

        void pwn_gpo() {
            const auto& gpo = control->get_global_properties();
            const auto override_time_us = override_time * 1000;
            const auto max_block_cpu_usage = gpo.configuration.max_transaction_cpu_usage;
            // auto pwnd_options = prod_plug->get_runtime_options();
            db->modify(gpo, [&](auto& dgp) {
                // pwnd_options.max_transaction_time = override_time;
                dgp.configuration.max_transaction_cpu_usage = override_time_us;
                ilog(
                    "new max_trx_cpu_usage value: ${pwnd_value}",
                    ("pwnd_value", gpo.configuration.max_transaction_cpu_usage)
                );
                if (override_time_us > max_block_cpu_usage) {
                    ilog(
                        "override_time (${otime}us) is > max_block_cpu_usage (${btime}us), overriding as well",
                        ("otime", override_time_us)("btime", max_block_cpu_usage)
                    );
                    dgp.configuration.max_block_cpu_usage = override_time_us;
                    // pwnd_options.max_block_cpu_usage = override_time_us;
                }
                should_perform_override = false;
                ilog("pwnd global_property_object!");
                // uint64_t CPU_TARGET = EOS_PERCENT(override_time_us, gpo.configuration.target_block_cpu_usage_pct);
                // auto& resource_limits = control->get_mutable_resource_limits_manager();
                // resource_limits.set_block_parameters(
                //     {
                //         CPU_TARGET,
                //         override_time_us,
                //         chain::config::block_cpu_usage_average_window_ms / chain::config::block_interval_ms,
                //         chain::config::maximum_elastic_resource_multiplier,
                //         {99, 100}, {1000, 999}
                //     },
                //     {
                //         EOS_PERCENT(gpo.configuration.max_block_net_usage, gpo.configuration.target_block_net_usage_pct),
                //         gpo.configuration.max_block_net_usage,
                //         chain::config::block_size_average_window_ms / chain::config::block_interval_ms,
                //         chain::config::maximum_elastic_resource_multiplier,
                //         {99, 100}, {1000, 999}
                //     }
                // );
                // ilog("updated block resource limits!");
                // prod_plug->update_runtime_options(pwnd_options);
                // ilog("updated producer_plugin runtime_options");
            });
        }
    };  // subst_plugin_impl

    subst_plugin::subst_plugin() :
        my(new subst_plugin_impl(app().get_io_service()))
    {}

    subst_plugin::~subst_plugin() {}

    void subst_plugin::set_program_options(options_description& cli, options_description& cfg) {
        auto options = cfg.add_options();
        options(
            "subst-by-name", bpo::value<vector<string>>()->composing(),
            "contract_name:new_contract.wasm. Whenever the contract deployed at \"contract_name\""
            "needs to run, substitute debug.wasm in "
            "its place and enable debugging support. This bypasses size limits, timer limits, and "
            "other constraints on debug.wasm. nodeos still enforces constraints on contract.wasm. "
            "(may specify multiple times)");
        options(
            "subst-manifest", bpo::value<string>()->default_value(std::string("")),
            "url. load susbtitution information from a remote json file.");
        options(
            "subst-manifest-interval", bpo::value<uint32_t>()->default_value(DEFAULT_MANIFEST_INTERVAL),
            "Time between manifest re-fetches");
        options(
            "subst-manifest-timeout", bpo::value<uint32_t>()->default_value(DEFAULT_MANIFEST_TIMEOUT),
            "Timeout for manifest http calls");
        options(
            "override-max-tx-time", bpo::value<uint32_t>(),
            "Override on chain max-transaction-time with value.");
    }

    void subst_plugin::plugin_initialize(const variables_map& options) {
        try {
            auto* _chain = app().find_plugin<chain_plugin>();

            my->init(_chain, options);

        } FC_LOG_AND_RETHROW()
    }

    void subst_plugin::plugin_startup() {}

    void subst_plugin::plugin_shutdown() {
        delete my->subst_ctx;
    }

    substitution_context& subst_plugin::context() {
        return *my->subst_ctx;
    }

    const subst_meta_object* substitution_context::get_by_account(const name& account, bool check_result) {
        const subst_meta_object* meta_ref = db->find<subst_meta_object, by_account>(account);

        if (check_result) {
            EOS_ASSERT(
                meta_ref,
                fc::assert_exception,
                "substitution metadata for account ${acc} not found!",
                ("acc", account)
            );
        }

        return meta_ref;
    }

    const account_metadata_object* substitution_context::get_account_metadata_object(const name& account, bool check_result) {
        const account_metadata_object* acc_meta = db->find<account_metadata_object, chain::by_name>(account);

        if (check_result) {
            EOS_ASSERT(
                acc_meta,
                fc::assert_exception,
                "account_metadata_object not found for ${acc}!",
                ("acc", account)
            );
        }

        return acc_meta;
    }


    const chain::code_object* substitution_context::get_codeobj(const name& account, bool check_result) {

        const auto& acc_meta = get_account_metadata_object(account, check_result);

        if (!acc_meta && !check_result) return nullptr;

        const chain::code_object* cobj = db->find<chain::code_object, chain::by_code_hash>(
            boost::make_tuple(acc_meta->code_hash, acc_meta->vm_type, acc_meta->vm_version));

        if (check_result) {
            EOS_ASSERT(
                cobj,
                fc::assert_exception,
                "code object for account ${acc}: (${hash},${vmt},${vmv}) not found!",
                ("acc", account)
                ("hash", acc_meta->code_hash)("vmt", acc_meta->vm_type)("vmv", acc_meta->vm_version)
            );
        }

        return cobj;
    }


    const digest_type substitution_context::get_codeobj_hash(const name& account, bool check_result) {
        const auto& cobj = get_codeobj(account, check_result);
        if (!cobj && !check_result) return digest_type();
        return digest_type::hash((const char*)cobj->code.data(), cobj->code.size());
    }


    void substitution_context::create(
        const name& account,
        uint64_t from_block,
        const std::vector<uint8_t>& code,
        bool must_activate
    ) {
        const auto& meta = db->create<subst_meta_object>([&](subst_meta_object& meta) {
            meta.account = account;
            meta.from_block = from_block;
            meta.s_code.assign(code.data(), code.size());
            meta.must_activate = must_activate;
        });
        ilog(
            "created new substitution metadata entry for ${acc} shash: ${shash}",
            ("acc", account)("shash", meta.s_hash())
        );
    }


    void substitution_context::update(
        const name& account,
        uint64_t from_block,
        const std::vector<uint8_t>& code,
        bool must_activate
    ) {
        const auto& meta_itr = get_by_account(account);

        auto hash = digest_type::hash((const char*)code.data(), code.size());

        db->modify(*meta_itr, [&](subst_meta_object& meta) {
            meta.s_code.assign(code.data(), code.size());
            meta.must_activate = must_activate;
        });

        ilog(
            "updated substitution metadata for ${acc} from block ${fblock} use ${hash}, current actual ${ahash}",
            ("acc", account)("fblock", from_block)("hash", hash)("ahash", get_codeobj_hash(account))
        );
    }

    void substitution_context::upsert(
        const name& account,
        uint64_t from_block,
        const std::vector<uint8_t>& code,
        bool must_activate
    ) {
        if(get_by_account(account, false))
            update(account, from_block, code, must_activate);

        else
            create(account, from_block, code, must_activate);
    }


    void substitution_context::upsert(
        std::string info,
        const std::vector<uint8_t>& code,
        bool must_activate
    ) {
        std::vector<std::string> v;
        boost::split(v, info, boost::is_any_of("-"));

        name account;
        auto from_block = 0;

        if (v.size() == 2) {
            account = name(v[0]);
            from_block = std::stoul(v[1]);

        } else
            account = name(info);

        upsert(account, from_block, code);
    }


    void substitution_context::activate(
        const name& account,
        bool save_og
    ) {
        const auto& meta = get_by_account(account);
        const auto& cobj = get_codeobj(account);

        if (save_og) {
            auto code = cobj->code;
            db->modify(*meta, [&](subst_meta_object& m) {
                m.og_code.assign(code.data(), code.size());
            });
        }

        db->modify(*cobj, [&](chain::code_object& o) {
            o.code.assign(meta->s_code.data(), meta->s_code.size());
            o.vm_type = 0;
            o.vm_version = 0;
        });
        reset_caches(account);

        ilog(
            "swapped ${acc}: ${hash} for ${shash}, actual: ${ahash}",
            ("acc", account)
            ("hash", meta->og_hash())
            ("shash", meta->s_hash())
            ("ahash", get_codeobj_hash(account))
        );
    }


    void substitution_context::reset_caches(const name& account) {

        const auto& cobj = get_codeobj(account);

        // remove wasm module cache if present
        auto& wasm_cache = control->get_wasm_interface().my->wasm_instantiation_cache;
        wasm_cache_index::iterator it = wasm_cache.find(
            boost::make_tuple(cobj->code_hash, cobj->vm_type, cobj->vm_version) );

        if (it != wasm_cache.end()) {
            wasm_cache.erase(it);
            ilog("removed ${acc} from wasm interface cache", ("acc", account));
        }

#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
        // remove eosvmoc code cache if present
        std::unique_ptr<eosvmoc_tier>& eosvmoc = get_eosvmoc();

        if (eosvmoc) {
            eosvmoc->cc.free_code(cobj->code_hash, cobj->vm_version);
            ilog("removed ${acc} from eosvmoc cache", ("acc", account));
        }
#endif
    }


    const std::set<name> substitution_context::get_substitutions() {
        std::set<name> subs;
        const auto& meta_idx = db->get_index<subst_meta_index, by_account>();
        for (auto itr = meta_idx.begin(); itr != meta_idx.end(); itr++)
            subs.insert(itr->account);

        return subs;
    }


    void substitution_context::deactivate(const name& account) {
        const auto& meta = get_by_account(account, false);
        const auto& cobj = get_codeobj(account, false);

        if (!cobj) return;

        const digest_type& cobj_hash = get_codeobj_hash(account);

        if (cobj_hash == meta->s_hash()) {
            db->modify(*cobj, [&](chain::code_object& o) {
                o.code.assign(meta->og_code.data(), meta->og_code.size());
                o.vm_type = 0;
                o.vm_version = 0;
            });
            ilog(
                "deactivated subst ${acc}, had ${hash} and set it back to ${ohash}",
                ("acc", account)
                ("hash", cobj_hash)
                ("ohash", meta->og_hash())
            );

            reset_caches(account);

        } else
            ilog("no need to deactivate ${acc}, subst not applied", ("acc", account));

        db->modify(*meta, [&](subst_meta_object& m) {
            m.must_activate = false;
        });
    }


    void substitution_context::remove(const name& account) {
        const subst_meta_object* acc = get_by_account(account, false);

        if (!acc) return;

        db->remove(*acc);
        ilog("removed substitution metadata for ${acc}", ("acc", account));
    }


    void substitution_context::debug_print() {
        ilog("substitution metadata on db: ");
        for (const name& acc : get_substitutions()) {
            const auto& meta = get_by_account(acc);
            ilog(
                "${id}: account \"${acc}\" from block ${fblock} "
                "on-chain hash: ${ohash} -> subst hash ${shash}",
                ("id", meta->id)
                ("acc", meta->account)
                ("fblock", meta->from_block)
                ("ohash", meta->og_hash())("shash", meta->s_hash())
            );
        }
    }


    void substitution_context::apply_hook(
        const digest_type& code_hash,
        uint8_t vm_type,
        uint8_t vm_version,
        eosio::chain::apply_context& context
    ) {
        const name& receiver = context.get_receiver();
        auto act = context.get_action();
        uint32_t block_num = context.control.pending_block_num();

        const auto& meta = get_by_account(receiver, false);

        if (!meta)
            return;  // no subst for this contract

        if (block_num >= meta->from_block && meta->must_activate) {  // if we are in subst range

            if (code_hash != meta->og_hash()) {  // on chain code changed for this account, need to store copy and swap
                ilog(
                    "action ${recv}::${aname}, must swap ${acc} cause code_hash (${chash}) != meta og hash(${ohash})",
                    ("recv", receiver)("aname", act.name)
                    ("acc", meta->account)
                    ("chash", code_hash)("ohash", meta->og_hash())
                );

                // perform swap
                activate(meta->account);

            } else if (get_codeobj_hash(meta->account) != meta->s_hash()) {  // new code for subst detected, re apply subst
                ilog(
                    "action ${recv}::${aname}, must swap ${acc} cause cobj hash (${chash}) != meta s hash(${shash})",
                    ("recv", receiver)("aname", act.name)
                    ("acc", meta->account)
                    ("chash", get_codeobj_hash(meta->account))("shash", meta->s_hash())
                );

                // perform swap, but dont copy cobj code to meta
                activate(meta->account, false);
            }
        }
    }


    void substitution_context::fetch_manifest(fc::microseconds timeout) {
        EOS_ASSERT(manifest_url, fc::assert_exception, "Tried to fetch manifest but no source configured");

        fc::url target_url = *manifest_url;

        string upath = target_url.path()->generic_string();

        if (!boost::algorithm::ends_with(upath, "subst.json"))
            wlog("looks like provided url based substitution manifest"
                    "doesn\'t end with \"susbt.json\"... trying anyways...");

        ilog("fetching manifest at ${url}", ("url", target_url));
        
        http_client cli;

        /*
        std::filesystem::path dest_path = destination_filename + _wallet_filename_extension;
        if( std::filesystem::exists(dest_path) ){
            std::filesystem::create_directories( dest_path );
        }

        std::filesystem::path dest_parent = std::filesystem::absolute(dest_path).parent_path();
        if( !std::filesystem::exists( dest_parent ) )
            std::filesystem::create_directories( dest_parent );
         std::filesystem::copy_file( src_path, dest_path, std::filesystem::copy_options::none );

         _wallet = fc::json::from_file( wallet_filename ).as< wallet_data >();
         string data = fc::json::to_pretty_string( _wallet );
         ofstream outfile{ wallet_filename };
         if (!outfile) {
            elog("Unable to open file: ${fn}", ("fn", wallet_filename));
            EOS_THROW(wallet_exception, "Unable to open file: ${fn}", ("fn", wallet_filename));
         }
         outfile.write( data.c_str(), data.length() );
         outfile.flush();
         outfile.close();
        */
        
        //return app().get_plugin<http_client_plugin>().get_client().post_sync(keosd_url, params, deadline).as<chain::signature_type>();
        //variant manifest = app().get_plugin<http_client_plugin>().get_client().get_sync_json(target_url, fc::time_point::now() + timeout);

        variant manifest = cli.get_sync_json(target_url, fc::time_point::now() + timeout);
        auto& manif_obj = manifest.get_object();

        ilog("got manifest from ${url}", ("url", target_url));

        string chain_id = control->get_chain_id();

        // remove all active substitutions
        for (const name& account : get_substitutions()) {
            deactivate(account);
            remove(account);
        }

        auto it = manif_obj.find(chain_id);
        if (it != manif_obj.end()) {
            for (auto subst_entry : (*it).value().get_object()) {
                string url_path = bpath(upath).remove_filename().generic_string();
                //https://evmwasms.s3.amazonaws.com/4667b205c6838ef70ff7988f6e8257e8be0e1284a2f59699054a018f743b1d11/0.1.3/regular.wasm
                std::filesystem::__cxx11::path wasm_url_path = url_path +"/"+ chain_id +"/"+ subst_entry.value().get_string();

                auto wasm_url = fc::url(
                    target_url.proto(), target_url.host(), target_url.user(), target_url.pass(),
                    wasm_url_path,
                    target_url.query(), target_url.args(), target_url.port()
                );

                ilog("downloading wasm from ${wurl}...", ("wurl", wasm_url));
                std::vector<uint8_t> new_code = cli.get_sync_raw(wasm_url, fc::time_point::now() + timeout);
                ilog("done.");

                std::string subst_info = subst_entry.key();
                upsert(subst_info, new_code);
            }
        } else {
            ilog("manifest found but chain id not present.");
        }
    }

}  // namespace eosio
