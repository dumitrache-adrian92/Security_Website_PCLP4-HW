import std.algorithm.iteration;
import std.algorithm.searching;
import std.array;
import std.ascii;
import std.conv;
import std.digest;
import std.digest.sha;
import std.random;
import std.range;
import std.stdio;
import std.string;
import std.typecons;

import vibe.db.mongo.mongo : connectMongoDB, MongoClient, MongoCollection;
import vibe.data.bson;

import dauth : makeHash, toPassword, parseHash;

struct DBConnection
{
    enum UserRet
    {
        OK,
        ERR_NULL_PASS,
        ERR_USER_EXISTS,
        ERR_INVALID_EMAIL,
        ERR_WRONG_USER,
        ERR_WRONG_PASS,
        NOT_IMPLEMENTED
    }

    this(string dbUser, string dbPassword, string dbAddr, string dbPort, string dbName)
    {
        this.client = connectMongoDB("mongodb://" ~ dbUser ~ ":" ~ dbPassword ~ "@" ~ dbAddr ~ ":" ~ dbPort);
        this.dbName = dbName;
    }

    // Optional helper
    static bool isValidEmail(string email)
    {
        if (email.empty)
        {
            return false;
        }

        auto res = email.find("@");
        // Check that we have some text before @
        // Check that @ is followed . and at least 2 chars after .
        immutable int min_suffix_len = 2;
        if (!res.empty && (email.length != res.length) && (res.find(".").length > min_suffix_len))
        {
            return true;
        }
        return false;
    }

    unittest
    {
        assert(isValidEmail("a@gmail.co"));
        assert(!isValidEmail("@gmail.co"));
        assert(!isValidEmail("a@gmail.o"));
        assert(!isValidEmail("a@gmailo"));
        assert(!isValidEmail("agmailo"));
    }

    UserRet addUser(string email, string username, string password, string name = "", string desc = "")
    {
        if (password.length == 0)
        {
            return UserRet.ERR_NULL_PASS;
        }

        if (!isValidEmail(email))
        {
            return UserRet.ERR_INVALID_EMAIL;
        }

        string collectionName = "users";
        MongoCollection users = client.getCollection(dbName ~ "." ~ collectionName);

        auto res = users.findOne(["_id": email]);
        if (res != Bson(null))
        {
            return UserRet.ERR_USER_EXISTS;
        }

        auto passHash = makeHash(toPassword(password.dup));
        writeln("pass hash = ", passHash.toString());
        users.insert(["_id": email,
                      "username": username,
                      "password": passHash.toString(),
                      "name": name,
                      "desc": desc]);

        // Query the database so that the above insertion propagates its effect.
        users.findOne(["_id": email]);

        return UserRet.OK;
    }

    auto getUserData(string email)
    {
        if (!isValidEmail(email))
        {
            return Bson(null);
        }

        string collectionName = "users";
        MongoCollection users = client.getCollection(dbName ~ "." ~ collectionName);

        return users.findOne(["_id": email]);
    }

    string generateUserAccessToken(string email)
    {
        string collectionName = "users";
        MongoCollection users = client.getCollection(dbName ~ "." ~ collectionName);

        auto user = users.findOne(["_id": email]);
        if (user == Bson(null))
        {
            // Return empty string if user does not exist
            return "";
        }

        string token;
        if (user.tryIndex("accessToken").isNull)
        {
            enum defaultPasswordChars = cast(immutable(ubyte)[]) (std.ascii.letters ~ std.ascii.digits);
            token = digest!SHA512(defaultPasswordChars.randomCover).toHexString().to!string();
            user["accessToken"] = token;
            users.update(["_id": email], user);
        }
        else
        {
            token = user["accessToken"].to!string.strip("\"");
        }
        return token;
    }

    string getUserAccessToken(string email)
    {
        string collectionName = "users";
        MongoCollection users = client.getCollection(dbName ~ "." ~ collectionName);

        auto user = users.findOne(["_id": email]);

        string token;
        if ((user != Bson(null)) && (!user.tryIndex("accessToken").isNull))
        {
            token = user["accessToken"].to!string.strip("\"");
        }
        return token;
    }

    UserRet authUser(string email, string password)
    {
        if (password.length == 0)
        {
            return UserRet.ERR_NULL_PASS;
        }

        if (!isValidEmail(email))
        {
            return UserRet.ERR_INVALID_EMAIL;
        }

        string collectionName = "users";
        MongoCollection users = client.getCollection(dbName ~ "." ~ collectionName);

        auto res = users.findOne(["_id": email]);
        if (res == Bson(null))
        {
            return UserRet.ERR_WRONG_USER;
        }

        // Password returned from mongo is wrapped inside quotes (") so we need to remove them before extracting salt
        auto userSalt = parseHash(res["password"].toString().strip("\"")).salt;

        // Compute hash with input pass and original signup salt, and compare the password hashes
        auto inputPassHash = makeHash(toPassword(password.dup), userSalt);
        if (res["password"].toString().strip("\"") != inputPassHash.toString())
        {
            return UserRet.ERR_WRONG_PASS;
        }

        return UserRet.OK;
    }

    UserRet deleteUser(string email)
    {
        if (!isValidEmail(email))
        {
            return UserRet.ERR_INVALID_EMAIL;
        }
        string collectionName = "users";
        MongoCollection users = client.getCollection(dbName ~ "." ~ collectionName);

        users.remove(["_id": email]);
        return UserRet.OK;
    }

    struct File
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        ubyte[] binData;
        string fileName;
        string digest;
        string securityLevel;
    }

    enum FileRet
    {
        OK,
        FILE_EXISTS,
        ERR_EMPTY_FILE,
        NOT_IMPLEMENTED
    }

    FileRet addFile(string userId, immutable ubyte[] binData, string fileName)
    {
        if (binData.empty)
        {
            return FileRet.ERR_EMPTY_FILE;
        }

        string collectionName = "files";
        MongoCollection files = client.getCollection(dbName ~ "." ~ collectionName);

        File file;
        file.id = BsonObjectID.generate();
        file.userId = userId;
        file.binData ~= binData;
        file.fileName = fileName;
        file.digest ~= digest!SHA512(file.binData).toHexString();

        Nullable!File fileExists = files.findOne!File(["digest": file.digest]);
        if (!fileExists.isNull)
        {
            return FileRet.FILE_EXISTS;
        }

        files.insert(file);
        return FileRet.OK;
    }

    File[] getFiles(string userId)
    {
        string collectionName = "files";
        MongoCollection files = client.getCollection(dbName ~ "." ~ collectionName);

        File[] userFiles;
        foreach(file; files.find!File(["userId": userId]))
        {
            userFiles ~= file;
        }
        return userFiles;
    }

    Nullable!File getFile(string digest)
    in(!digest.empty)
    do
    {
        string collectionName = "files";
        MongoCollection files = client.getCollection(dbName ~ "." ~ collectionName);

        Nullable!File file = files.findOne!File(["digest": digest]);
        return file;
    }

    void deleteFile(string email, string digest)
    in(!digest.empty)
    do
    {
        string collectionName = "files";
        MongoCollection files = client.getCollection(dbName ~ "." ~ collectionName);
        files.remove(["userId": email, "digest": digest]);
    }

    struct Url
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        string addr;
        string securityLevel;
        string[] aliases;
    }

    enum UrlRet
    {
        OK,
        URL_EXISTS,
        ERR_EMPTY_URL,
        NOT_IMPLEMENTED
    }

    UrlRet addUrl(string userId, string urlAddress)
    {
        if (urlAddress.empty)
        {
            return UrlRet.ERR_EMPTY_URL;
        }

        string collectionName = "urls";
        MongoCollection urls = client.getCollection(dbName ~ "." ~ collectionName);

        Nullable!Url urlExists = urls.findOne!Url(["addr": urlAddress]);
        if (!urlExists.isNull)
        {
            return UrlRet.URL_EXISTS;
        }

        Url url;
        url.id = BsonObjectID.generate();
        url.userId = userId;
        url.addr = urlAddress;

        urls.insert(url);
        return UrlRet.OK;
    }

    Url[] getUrls(string userId)
    {
        string collectionName = "urls";
        MongoCollection urls = client.getCollection(dbName ~ "." ~ collectionName);

        Url[] userUrls;
        foreach(url; urls.find!Url(["userId": userId]))
        {
            userUrls ~= url;
        }
        return userUrls;
    }

    Nullable!Url getUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
        string collectionName = "urls";
        MongoCollection urls = client.getCollection(dbName ~ "." ~ collectionName);

        Nullable!Url url = urls.findOne!Url(["addr": urlAddress]);
        return url;
    }

    void deleteUrl(string email, string urlAddress)
    in(!urlAddress.empty)
    do
    {
        string collectionName = "urls";
        MongoCollection urls = client.getCollection(dbName ~ "." ~ collectionName);
        urls.remove(["userId": email, "addr": urlAddress]);
    }

private:
    MongoClient client;
    string dbName;
}

unittest
{
    auto helper = DBConnection("root", "example", "127.0.0.1", "27017", "testing");

    const email = "edi@gmail.com";

    // Test addUser
    auto userRes = helper.addUser(email, "edi", "aaa");
    assert(userRes == DBConnection.UserRet.ERR_INVALID_EMAIL);

    userRes = helper.addUser(email, "edi", "");
    assert(userRes == DBConnection.UserRet.ERR_NULL_PASS);

    userRes = helper.addUser(email, "edi", "aaa");
    assert(userRes == DBConnection.UserRet.OK);

    userRes = helper.addUser(email, "edi", "aaa");
    assert(userRes == DBConnection.UserRet.ERR_USER_EXISTS);

    // Test authUser
    userRes = helper.authUser(email, "aaa");
    assert(userRes == DBConnection.UserRet.ERR_INVALID_EMAIL);

    userRes = helper.authUser(email, "");
    assert(userRes == DBConnection.UserRet.ERR_NULL_PASS);

    userRes = helper.authUser(email, "abc");
    assert(userRes == DBConnection.UserRet.ERR_WRONG_PASS);

    userRes = helper.authUser(email, "aaa");
    assert(userRes == DBConnection.UserRet.OK);

    // Test deleteUser
    userRes = helper.deleteUser(email);
    assert(userRes == DBConnection.UserRet.OK);
}

unittest
{
    auto helper = DBConnection("root", "example", "127.0.0.1", "27017", "testing");

    const email = "edi@gmail.com";

    // Test addFile
    auto fileRes = helper.addFile(email, [], "test");
    assert(fileRes == DBConnection.FileRet.ERR_EMPTY_FILE);

    fileRes = helper.addFile(email, [1, 2, 3, 4, 5], "test");
    assert(fileRes == DBConnection.FileRet.OK);

    fileRes = helper.addFile(email, [1, 2, 3, 4, 5], "test");
    assert(fileRes == DBConnection.FileRet.FILE_EXISTS);

    // Test getFile
    ubyte[] data = [1, 2, 3, 4, 5];
    auto dataDigest = digest!SHA512(data).toHexString().to!string;
    auto fileExists = helper.getFile(dataDigest);
    assert(!fileExists.isNull);

    dataDigest = digest!SHA512(data[1..$]).toHexString().to!string;
    fileExists = helper.getFile(dataDigest);
    assert(fileExists.isNull);

    // Test getFiles
    auto files = helper.getFiles(email);
    assert(!files.empty);
    files = helper.getFiles("non-existent@gmail.com");
    assert(files.empty);

    // Test deleteFile
    dataDigest = digest!SHA512(data).toHexString().to!string;
    helper.deleteFile(email, dataDigest);
    fileExists = helper.getFile(dataDigest);
    assert(fileExists.isNull);
}

unittest
{
    auto helper = DBConnection("root", "example", "mongo", "27017", "testing");

    const email = "edi@gmail.com";

    // Test addUrl
    auto urlRes = helper.addUrl(email, "");
    assert(urlRes == DBConnection.UrlRet.ERR_EMPTY_URL);

    urlRes = helper.addUrl(email, "123.net");
    assert(urlRes == DBConnection.UrlRet.OK);

    urlRes = helper.addUrl(email, "123.net");
    assert(urlRes == DBConnection.UrlRet.URL_EXISTS);

    // Test getUrl
    auto urlExists = helper.getUrl("123.net");
    assert(!urlExists.isNull);

    urlExists = helper.getUrl("123et");
    assert(urlExists.isNull);

    // Test getUrls
    auto urls = helper.getUrls(email);
    assert(!urls.empty);
    urls = helper.getUrls("non-existent@gmail.com");
    assert(urls.empty);

    // Test deleteFile
    helper.deleteUrl(email, "123.net");
    urlExists = helper.getUrl("123.net");
    assert(urlExists.isNull);
}
