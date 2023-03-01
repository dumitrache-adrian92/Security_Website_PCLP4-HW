import vibe.vibe;
import virus_total;
import db_conn;

import std.stdio;

void main()
{
    auto dbClient = DBConnection("root", "example", "mongo", "27017", "testing");
    auto virusTotalAPI = new VirusTotalAPI(dbClient);

    auto router = new URLRouter;
    router.registerRestInterface(virusTotalAPI);
    router.get("/", &main_page);
    router.get("/login", &login_page);
    router.get("/register", &register_page);
    router.get("/user", &user_page);

    auto settings = new HTTPServerSettings;
    settings.port = 8080;
    settings.bindAddresses = ["0.0.0.0"];
    auto listener = listenHTTP(settings, router);

    logInfo("Please open http://localhost:8080/ in your browser.");

    runApplication();
}

void main_page(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("index.dt")(res);
}

void login_page(HTTPServerRequest req, HTTPServerResponse res) {
    render!("login.dt")(res);
}

void register_page(HTTPServerRequest req, HTTPServerResponse res) {
    render!("register.dt")(res);
}

void user_page(HTTPServerRequest req, HTTPServerResponse res) {
    render!("user.dt")(res);
}
