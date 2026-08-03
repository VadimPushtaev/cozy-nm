from cozy_network_manager.app.ui.templates import templates


def test_bridge_templates_load():
    templates.env.get_template("dashboard.html")
    templates.env.get_template("forwards.html")
    templates.env.get_template("bridge_form.html")
