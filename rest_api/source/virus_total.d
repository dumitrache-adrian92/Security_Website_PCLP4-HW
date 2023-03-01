import std.conv;
import std.digest;
import std.digest.sha;
import std.stdio;

import vibe.d;
import vibe.web.auth;

import db_conn;

static struct AuthInfo
{
@safe:
    string userEmail;
}

@path("api/v1")
@requiresAuth
interface VirusTotalAPIRoot
{
    // Users management
    @noAuth
    @method(HTTPMethod.POST)
    @path("signup")
    Json addUser(string userEmail, string username, string password, string name = "", string desc = "");

    @noAuth
    @method(HTTPMethod.POST)
    @path("login")
    Json authUser(string userEmail, string password);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_user")
    Json deleteUser(string userEmail);

    // URLs management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_url") // the path could also be "/url/add", thus defining the url "namespace" in the URL
    Json addUrl(string userEmail, string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path("url_info")
    Json getUrlInfo(string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path ("user_urls")
    Json getUserUrls(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_url")
    Json deleteUrl(string userEmail, string urlAddress);

    // Files management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_file")
    Json addFile(string userEmail, immutable ubyte[] binData, string fileName);

    @noAuth
    @method(HTTPMethod.GET)
    @path("file_info")
    Json getFileInfo(string fileSHA512Digest);

    @noAuth
    @method(HTTPMethod.GET)
    @path("user_files")
    Json getUserFiles(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_file")
    Json deleteFile(string userEmail, string fileSHA512Digest);
}

class VirusTotalAPI : VirusTotalAPIRoot
{
    this(DBConnection dbClient)
    {
        this.dbClient = dbClient;
    }

    @noRoute AuthInfo authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        // If "userEmail" is not present, an error 500 (ISE) will be returned
        string userEmail = req.json["userEmail"].get!string;
        string userAccessToken = dbClient.getUserAccessToken(userEmail);
        // Use headers.get to check if key exists
        string headerAccessToken = req.headers.get("AccessToken");
        if (headerAccessToken && headerAccessToken == userAccessToken)
            return AuthInfo(userEmail);
        throw new HTTPStatusException(HTTPStatus.unauthorized);
    }

override:

    Json addUser(string userEmail, string username, string password, string name = "", string desc = "")
    {
        logInfo("inside addUser\n");
        auto res = dbClient.addUser(userEmail, username, password, name, desc);
        logInfo("res = %s\n", res);
        switch (res)
        {
            case DBConnection.UserRet.OK:
                return format("User %s with email %s was added to the database. Please login.", username, userEmail).serializeToJson();

            case DBConnection.UserRet.ERR_INVALID_EMAIL:
                throw new HTTPStatusException(HTTPStatus.badRequest, format("[Error] User email %s is invalid", userEmail));

            case DBConnection.UserRet.ERR_NULL_PASS:
                throw new HTTPStatusException(HTTPStatus.badRequest, "[Error] User password cannot be empty");

            case DBConnection.UserRet.ERR_USER_EXISTS:
                throw new HTTPStatusException(HTTPStatus.unauthorized, "[Error] Username or email already exists");

            default:
                throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
        }
    }

    Json authUser(string userEmail, string password)
    {
        auto res = dbClient.authUser(userEmail, password);
        switch (res)
        {
            case DBConnection.UserRet.OK:
                return ["AccessToken": dbClient.generateUserAccessToken(userEmail)].serializeToJson();

            case DBConnection.UserRet.ERR_INVALID_EMAIL:
                throw new HTTPStatusException(HTTPStatus.badRequest, format("[Error] User email %s is invalid", userEmail));

            case DBConnection.UserRet.ERR_NULL_PASS:
                throw new HTTPStatusException(HTTPStatus.badRequest, format("[Error] User password cannot be empty"));

            case DBConnection.UserRet.ERR_WRONG_USER:
            case DBConnection.UserRet.ERR_WRONG_PASS:
                throw new HTTPStatusException(HTTPStatus.unauthorized, "[Error] Username or password was incorrect");

            default:
                throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
        }
    }

    Json deleteUser(string userEmail)
    {
        auto res = dbClient.deleteUser(userEmail);
        if (res == DBConnection.UserRet.ERR_INVALID_EMAIL)
        {
            throw new HTTPStatusException(HTTPStatus.badRequest,
                        format("[Error] Could not delete user with email %s. Email is invalid", userEmail));
        }
        return format("User with email %s was deleted", userEmail).serializeToJson();
    }

    // URLs management
    Json addUrl(string userEmail, string urlAddress)
    {
        auto res = dbClient.addUrl(userEmail, urlAddress);
        final switch (res)
        {
            case DBConnection.UrlRet.OK:
                return format("URL %s was added to the database and will be inspected", urlAddress).serializeToJson();

            case DBConnection.UrlRet.URL_EXISTS:
                auto url = dbClient.getUrl(urlAddress);
                return format("URL %s is already present in the database. Please see bellow what we already know about it\n%s",
                              urlAddress, url.serializeToPrettyJson()).serializeToJson();

            case DBConnection.UrlRet.ERR_EMPTY_URL:
                throw new HTTPStatusException(HTTPStatus.badRequest, "[Error] URL address cannot be empty");

            case DBConnection.UrlRet.NOT_IMPLEMENTED:
                throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
        }
    }

    Json deleteUrl(string userEmail, string urlAddress)
    {
        if (urlAddress.empty)
        {
            throw new HTTPStatusException(HTTPStatus.badRequest, "[Error] URL address cannot be empty");
        }
        dbClient.deleteUrl(userEmail, urlAddress);
        return format("URL %s was deleted", urlAddress).serializeToJson();
    }

    Json getUrlInfo(string urlAddress)
    {
        auto url = dbClient.getUrl(urlAddress);
        if (url.isNull)
        {
            throw new HTTPStatusException(HTTPStatus.notFound, format("[Error] URL address %s does not exist in the database", urlAddress));
        }
        return url.serializeToJson();
    }

    Json getUserUrls(string userEmail)
    {
        return dbClient.getUrls(userEmail).serializeToJson();
    }

    // Files management

    Json addFile(string userEmail, immutable ubyte[] binData, string fileName)
    {
        auto res = dbClient.addFile(userEmail, binData, fileName);
        final switch (res)
        {
            case DBConnection.FileRet.OK:
                return format("File %s was added to the database and will be inspected", fileName).serializeToJson();

            case DBConnection.FileRet.FILE_EXISTS:
                auto dataDigest = digest!SHA512(binData).toHexString().to!string;
                auto file = dbClient.getFile(dataDigest);
                return format("File %s is already present in the database. Please see bellow what we already know about it\n%s",
                              fileName, file.serializeToPrettyJson()).serializeToJson();

            case DBConnection.FileRet.ERR_EMPTY_FILE:
                throw new HTTPStatusException(HTTPStatus.badRequest, format("[Error] File data cannot be empty"));

            case DBConnection.FileRet.NOT_IMPLEMENTED:
                throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
        }
    }

    Json getFileInfo(string fileSHA512Digest)
    {
        auto file = dbClient.getFile(fileSHA512Digest);
        if (file.isNull)
        {
            throw new HTTPStatusException(HTTPStatus.notFound, format("[Error] file with SHA512 digest %s does not exist in the database", fileSHA512Digest));
        }
        return file.serializeToJson();
    }

    Json getUserFiles(string userEmail)
    {
        return dbClient.getFiles(userEmail).serializeToJson();
    }

    Json deleteFile(string userEmail, string fileSHA512Digest)
    {
        if (fileSHA512Digest.empty)
        {
            throw new HTTPStatusException(HTTPStatus.badRequest, "[Error] File digest cannot be empty");
        }
        dbClient.deleteFile(userEmail, fileSHA512Digest);
        return format("File %s was deleted", fileSHA512Digest).serializeToJson();
    }

private:
    DBConnection dbClient;
}
