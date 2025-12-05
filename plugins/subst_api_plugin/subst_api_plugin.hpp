#pragma once

#include <fc/time.hpp>
#include <eosio/http_plugin/http_plugin.hpp>

#include "subst_api_plugin.hpp"
#include "subst_plugin.hpp"
#include "api.hpp"


namespace eosio {

    using namespace appbase;

    class subst_api_plugin : public plugin<subst_api_plugin> {
        public:
            APPBASE_PLUGIN_REQUIRES((subst_plugin)(http_plugin))

            subst_api_plugin();
            virtual ~subst_api_plugin() override;

            void set_program_options(options_description& cli, options_description& cfg) override;
            void plugin_initialize(const variables_map& options);
            void plugin_startup();
            void plugin_shutdown();
    };

}  // namespace eosio
