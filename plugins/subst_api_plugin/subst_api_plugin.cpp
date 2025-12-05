#include "subst_api_plugin.hpp"

namespace eosio {

    static auto _subst_api_plugin = application::register_plugin<subst_api_plugin>();

    subst_api_plugin::subst_api_plugin() {}
    subst_api_plugin::~subst_api_plugin() {}

    void subst_api_plugin::set_program_options(options_description& cli, options_description& cfg) {
        auto options = cfg.add_options();
        options(
            "subst-admin-apis", bpo::bool_switch()->default_value(false),
            "Enable subst apis that perform metadata changes");
    }

    void subst_api_plugin::plugin_initialize(const variables_map& options) {
        try {
            // lifetime of plugin is lifetime of application
            auto& subst_plug = app().get_plugin<subst_plugin>();
            auto& http_plug = app().get_plugin<http_plugin>();

            subst_apis subst_api(http_plug.get_max_response_time(), subst_plug.context());

            // read only
            http_plug.add_api({
                SUBST_CALL(status, 200, http_params_types::possible_no_params)
            }, appbase::exec_queue::read_only);
            
            // read-write
            if (options.at("subst-admin-apis").as<bool>()) {
                wlog("subst-admin-apis enabled, don\'t expose these to ");
                http_plug.add_api({
                    SUBST_CALL(upsert,         200, http_params_types::params_required),
                    SUBST_CALL(activate,       200, http_params_types::possible_no_params),
                    SUBST_CALL(deactivate,     200, http_params_types::possible_no_params),
                    SUBST_CALL(remove,         200, http_params_types::possible_no_params),

                    SUBST_CALL(fetch_manifest, 200, http_params_types::no_params)
                }, appbase::exec_queue::read_write, appbase::priority::medium_high);
            }
        } FC_LOG_AND_RETHROW()
    }

    void subst_api_plugin::plugin_startup() {
        ilog("starting subst_api_plugin");
    }

    void subst_api_plugin::plugin_shutdown() {}

}  // namespace eosio
