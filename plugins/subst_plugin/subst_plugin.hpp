#pragma once

#include <eosio/vm/backend.hpp>

#include <eosio/chain/config.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/application.hpp>
#include <eosio/chain/apply_context.hpp>
#include <eosio/chain/contract_types.hpp>
#include <eosio/chain/transaction_context.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/http_client_plugin/http_client_plugin.hpp>
#include <eosio/chain/global_property_object.hpp>

#include "substitution_context.hpp"

#define DEFAULT_OVERRIDE_TIME 300
#define DEFAULT_MANIFEST_INTERVAL 300
#define DEFAULT_MANIFEST_TIMEOUT 5


namespace eosio {

    using namespace appbase;

    using chain::controller;
    using chainbase::database;

    class subst_plugin_impl;

    class subst_plugin : public plugin<subst_plugin> {
        public:
            APPBASE_PLUGIN_REQUIRES((chain_plugin)(http_client_plugin))

            subst_plugin();
            virtual ~subst_plugin() override;

            void set_program_options(options_description& cli, options_description& cfg) override;
            void plugin_initialize(const variables_map& options);
            void plugin_startup();
            void plugin_shutdown();

            substitution_context& context();

        private:
            std::shared_ptr<subst_plugin_impl> my;
    };

}  // namespace eosio
