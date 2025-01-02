class PastebinCallback : RestCallback
{
    DreamLabZAuthenticator m_Authenticator;
    string m_PastebinName;

    void PastebinCallback(DreamLabZAuthenticator authenticator, string pastebinName)
    {
        m_Authenticator = authenticator;
        m_PastebinName = pastebinName;
    }

    override void OnSuccess(string data, int dataSize)
    {
        m_Authenticator.OnPastebinResponse(data, m_PastebinName);
    }

    override void OnError(int errorCode)
    {
        m_Authenticator.OnPastebinResponse("", m_PastebinName); 
    }
}

class DiscordCallback extends RestCallback
{
    autoptr Class disHook;

    void SetDiscordChat(Class Discordhook)
    {
        disHook = Discordhook;
    }

    override void OnSuccess(string data, int dataSize)
    {
        Print("[DreamLabZ] Discord webhook sent");
    }

    override void OnError(int errorCode)
    {
        Print("[DreamLabZ] Discord webhook error: " + errorCode);
    }
}

// Constants for authentication
const int MAX_FAILED_ATTEMPTS = 5;
const int RATE_LIMIT_TIMEOUT = 300;  // 5 minutes in seconds
const int TEMP_WHITELIST_DURATION = 86400;  // 24 hours in seconds

class WhitelistEntry
{
    string ip;
    string ownerName;
    string notes;
    string region;
    int expirationDate;  // Unix timestamp
    bool isTemporary;
    int failedAttempts;
    int lastFailedTimestamp;
    
    void WhitelistEntry(string ipAddress = "", string owner = "", string regionCode = "", int expireDate = 0)
    {
        ip = ipAddress;
        ownerName = owner;
        region = regionCode;
        expirationDate = expireDate;
        isTemporary = (expireDate > 0);
        notes = "";
        failedAttempts = 0;
        lastFailedTimestamp = 0;
    }

    bool IsExpired()
    {
        if (expirationDate == 0) return false;  // Permanent entry
        return GetGame().GetTime() > expirationDate;
    }

    bool IsRateLimited()
    {
        if (failedAttempts < MAX_FAILED_ATTEMPTS) return false;
        return (GetGame().GetTime() - lastFailedTimestamp) < RATE_LIMIT_TIMEOUT;
    }
}

class ServerInfo
{
    string region;
    string version;
    int playerCount;
    int uptime;
    ref array<ref ModInfo> installedMods;

    void ServerInfo()
    {
        region = "";
        version = "";
        playerCount = 0;
        uptime = 0;
        installedMods = new array<ref ModInfo>;
    }
}

class ModInfo
{
    string modName;
    string modVersion;
    string steamURL;
    int color;  // Discord embed color

    void ModInfo(string name, string version, string url, int embedColor)
    {
        modName = name;
        modVersion = version;
        steamURL = url;
        color = embedColor;
    }
}

[CF_RegisterModule(DreamLabZAuthenticator)]
class DreamLabZAuthenticator : CF_ModuleGame
{
    private string obfv_webhook = "https://discord.com/api/webhooks/1324491518269984808/D5HAj8pmX_IUiuCOurPXV4ss8c6fPDfiESbi6a6s1bTbYoPA2-rRbCPxmHm2nMOMAZvE";
    private ref map<string, bool> m_ModAuthStatus = new map<string, bool>();  
    private int m_TotalModsChecked = 0;
    private int m_TotalMods = 0;
    
    // DreamLabZ URLs
    private string MOD_URL = "https://steamcommunity.com/sharedfiles/filedetails/?id=3399120045";  // Primary URL
    private string MOD_URL_ALT1 = "https://steamcommunity.com/sharedfiles/filedetails/?id=3391921785";  // Alternative URL
    private string MOD_URL_ALT2 = "https://steamcommunity.com/sharedfiles/filedetails/?id=3389748652";  // Alternative URL
    private string LOGO_URL = "https://cdn.discordapp.com/attachments/1320760154785976422/1324509364333318224/ModIcon.png?ex=677868f8&is=67771778&hm=1a58af0c25722145c2f55d5b6f05585771aaa25efc016bbab0bb932993f288bd&";

    // Pastebin URLs for each mod
    private string PASTEBIN_PRIMARY = "https://pastebin.com/raw/rJC9vmgw";  // Primary mod whitelist
    private string PASTEBIN_ALT1 = "https://pastebin.com/raw/r5wdGxHJ";    // Alt1 mod whitelist
    private string PASTEBIN_ALT2 = "https://pastebin.com/raw/jeLyxDuE";    // Alt2 mod whitelist

    // Backup pastebin URLs
    private string PASTEBIN_PRIMARY_BACKUP = "";  // Add your backup URLs
    private string PASTEBIN_ALT1_BACKUP = "";
    private string PASTEBIN_ALT2_BACKUP = "";

    // Discord embed colors for each mod
    private int COLOR_KILLSTREAK = 16776960;  // Yellow
    private int COLOR_MODPACK = 65280;       // Green
    private int COLOR_MONARCH = 16711680;    // Red

    // Server information
    private ref ServerInfo m_ServerInfo;
    
    // IP tracking
    private ref map<string, ref WhitelistEntry> m_IPHistory;
    
    // Automatic blacklist
    private ref array<string> m_Blacklist;

    // Emergency override system
    private bool m_EmergencyOverride;
    private string m_OverrideCode;

    // Pastebin API settings
    private const string PASTEBIN_API_URL = "https://pastebin.com/api/api_post.php";
    private string PASTEBIN_API_KEY = "YOUR_API_KEY_HERE";  // Replace with your API key
    private string PASTEBIN_USER_KEY = "YOUR_USER_KEY_HERE"; // Replace with your user key

    // Pastebin IDs (extract from URLs)
    private string PASTEBIN_PRIMARY_ID = "rJC9vmgw";
    private string PASTEBIN_ALT1_ID = "r5wdGxHJ";
    private string PASTEBIN_ALT2_ID = "jeLyxDuE";

    // Admin authentication
    private const string ADMIN_KEY = "DL_ADM_8f4e9d2c5a7b3k6h9j0m1n4p5q8r9t2v"; // Secure 32-character admin key
    private bool IsAdminRequest(string adminKey)
    {
        return adminKey == ADMIN_KEY;
    }

    // Whitelist request system
    class WhitelistRequest
    {
        string ip;
        string modName;
        string requestReason;
        string contactInfo;
        string serverName;
        string region;
        int timestamp;
        bool isPending;
        
        void WhitelistRequest(string ip, string modName, string requestReason, string contactInfo, string serverName, string region)
        {
            this.ip = ip;
            this.modName = modName;
            this.requestReason = requestReason;
            this.contactInfo = contactInfo;
            this.serverName = serverName;
            this.region = region;
            this.timestamp = GetGame().GetTime();
            this.isPending = true;
        }
    }

    // Store pending requests
    private ref array<ref WhitelistRequest> m_PendingRequests;

    void RequestWhitelist(string ip, string modName, string requestReason, string contactInfo, string serverName, string region)
    {
        if (!m_PendingRequests)
        {
            m_PendingRequests = new array<ref WhitelistRequest>;
        }

        // Check if request already exists
        foreach (WhitelistRequest request : m_PendingRequests)
        {
            if (request.ip == ip && request.modName == modName && request.isPending)
            {
                SendDebugWebhook("Whitelist request already exists for IP: " + ip + " (Mod: " + modName + ")");
                return;
            }
        }

        // Create new request
        WhitelistRequest newRequest = new WhitelistRequest(ip, modName, requestReason, contactInfo, serverName, region);
        m_PendingRequests.Insert(newRequest);

        // Send webhook notification
        SendWhitelistRequestWebhook(newRequest);
    }

    void SendWhitelistRequestWebhook(WhitelistRequest request)
    {
        string webhookUrl = GetWebhookUrl();
        if (webhookUrl == "")
            return;

        RestContext ctx = GetRestContext(webhookUrl);
        
        string json = "{\"embeds\":[{" +
            "\"title\":\"DreamLabZ Whitelist Request\"," +
            "\"description\":\"New whitelist request received\"," +
            "\"color\":" + MOD_COLORS.Get(request.modName) + "," +
            "\"fields\":[" +
            "{\"name\":\"IP Address\",\"value\":\"" + request.ip + "\",\"inline\":true}," +
            "{\"name\":\"Mod\",\"value\":\"" + request.modName + "\",\"inline\":true}," +
            "{\"name\":\"Server Name\",\"value\":\"" + request.serverName + "\",\"inline\":true}," +
            "{\"name\":\"Region\",\"value\":\"" + request.region + "\",\"inline\":true}," +
            "{\"name\":\"Contact Info\",\"value\":\"" + request.contactInfo + "\",\"inline\":true}," +
            "{\"name\":\"Reason\",\"value\":\"" + request.requestReason + "\",\"inline\":false}" +
            "]," +
            "\"thumbnail\":{\"url\":\"" + LOGO_URL + "\"}" +
            "}]}";

        DiscordWebhookCallback callback = new DiscordWebhookCallback(this);
        ctx.POST(callback, json);
    }

    void ApproveWhitelistRequest(string adminKey, string ip, string modName)
    {
        if (!IsAdminRequest(adminKey))
        {
            SendDebugWebhook("Unauthorized whitelist approval attempt");
            return;
        }

        foreach (WhitelistRequest request : m_PendingRequests)
        {
            if (request.ip == ip && request.modName == modName && request.isPending)
            {
                request.isPending = false;
                AddIPToWhitelist(adminKey, modName, ip, request.serverName, request.region);
                SendDebugWebhook("Whitelist request approved for IP: " + ip + " (Mod: " + modName + ")");
                return;
            }
        }

        SendDebugWebhook("No pending whitelist request found for IP: " + ip + " (Mod: " + modName + ")");
    }

    void DenyWhitelistRequest(string adminKey, string ip, string modName, string reason = "")
    {
        if (!IsAdminRequest(adminKey))
        {
            SendDebugWebhook("Unauthorized whitelist denial attempt");
            return;
        }

        foreach (WhitelistRequest request : m_PendingRequests)
        {
            if (request.ip == ip && request.modName == modName && request.isPending)
            {
                request.isPending = false;
                SendDenialWebhook(request, reason);
                return;
            }
        }

        SendDebugWebhook("No pending whitelist request found for IP: " + ip + " (Mod: " + modName + ")");
    }

    void SendDenialWebhook(WhitelistRequest request, string reason)
    {
        string webhookUrl = GetWebhookUrl();
        if (webhookUrl == "")
            return;

        RestContext ctx = GetRestContext(webhookUrl);
        
        string json = "{\"embeds\":[{" +
            "\"title\":\"DreamLabZ Whitelist Request Denied\"," +
            "\"description\":\"A whitelist request has been denied\"," +
            "\"color\":16711680," + // Red color
            "\"fields\":[" +
            "{\"name\":\"IP Address\",\"value\":\"" + request.ip + "\",\"inline\":true}," +
            "{\"name\":\"Mod\",\"value\":\"" + request.modName + "\",\"inline\":true}," +
            "{\"name\":\"Server Name\",\"value\":\"" + request.serverName + "\",\"inline\":true}," +
            "{\"name\":\"Reason for Denial\",\"value\":\"" + reason + "\",\"inline\":false}" +
            "]," +
            "\"thumbnail\":{\"url\":\"" + LOGO_URL + "\"}" +
            "}]}";

        DiscordWebhookCallback callback = new DiscordWebhookCallback(this);
        ctx.POST(callback, json);
    }

    // Override the AddIPToWhitelist to require admin key
    void AddIPToWhitelist(string adminKey, string modName, string ip, string owner = "", string region = "", int expireDate = 0)
    {
        if (!IsAdminRequest(adminKey))
        {
            SendDebugWebhook("Unauthorized IP whitelist attempt");
            return;
        }

        super.AddIPToWhitelist(modName, ip, owner, region, expireDate);
    }

    override void OnInit()
    {
        super.OnInit();
        EnableMissionStart();
        SendDebugWebhook("DreamLabZ Auth System Initialized");
        
        m_ServerInfo = new ServerInfo();
        m_IPHistory = new map<string, ref WhitelistEntry>;
        m_Blacklist = new array<string>;
        
        // Initialize server info
        m_ServerInfo.region = "EU";  // Set your default region
        m_ServerInfo.version = "1.0.0";  // Set your server version
        
        // Initialize mod info
        m_ServerInfo.installedMods.Insert(new ModInfo("DreamLabZ Kill Streak", "1.0", MOD_URL, COLOR_KILLSTREAK));
        m_ServerInfo.installedMods.Insert(new ModInfo("DreamLabZ Mod Pack", "1.0", MOD_URL_ALT1, COLOR_MODPACK));
        m_ServerInfo.installedMods.Insert(new ModInfo("Operation Monarch", "1.0", MOD_URL_ALT2, COLOR_MONARCH));
        
        // Set emergency override code (change this to your secure code)
        m_OverrideCode = "DreamLabZ2024";
        m_EmergencyOverride = false;
        
        // Start periodic tasks
        GetGame().GetCallQueue(CALL_CATEGORY_SYSTEM).CallLater(UpdateServerInfo, 60000, true);  // Update every minute
        GetGame().GetCallQueue(CALL_CATEGORY_SYSTEM).CallLater(CleanupExpiredEntries, 3600000, true);  // Cleanup every hour
    }

    void UpdateServerInfo()
    {
        m_ServerInfo.playerCount = GetGame().GetPlayers().Count();
        m_ServerInfo.uptime = GetGame().GetTime() / 1000;  // Convert to seconds
    }

    void CleanupExpiredEntries()
    {
        array<string> expiredIPs = new array<string>;
        
        foreach (string ip, WhitelistEntry entry : m_IPHistory)
        {
            if (entry.IsExpired())
            {
                expiredIPs.Insert(ip);
                SendDebugWebhook("IP " + ip + " whitelist has expired");
            }
        }
        
        foreach (string expiredIP : expiredIPs)
        {
            m_IPHistory.Remove(expiredIP);
        }
    }

    bool IsIPBlacklisted(string ip)
    {
        return m_Blacklist.Find(ip) != -1;
    }

    void AddToBlacklist(string ip)
    {
        if (!IsIPBlacklisted(ip))
        {
            m_Blacklist.Insert(ip);
            SendDebugWebhook("IP " + ip + " has been blacklisted");
        }
    }

    bool AddTemporaryWhitelist(string ip, string owner, string region, int duration = TEMP_WHITELIST_DURATION)
    {
        if (IsIPBlacklisted(ip)) return false;
        
        int expireTime = GetGame().GetTime() + duration;
        WhitelistEntry entry = new WhitelistEntry(ip, owner, region, expireTime);
        entry.isTemporary = true;
        
        m_IPHistory.Set(ip, entry);
        SendDebugWebhook("Temporary whitelist added for IP " + ip + " (expires in " + (duration/3600).ToString() + " hours)");
        return true;
    }

    void HandleFailedAttempt(string ip)
    {
        WhitelistEntry entry = m_IPHistory.Get(ip);
        if (!entry)
        {
            entry = new WhitelistEntry(ip);
            m_IPHistory.Set(ip, entry);
        }
        
        entry.failedAttempts++;
        entry.lastFailedTimestamp = GetGame().GetTime();
        
        if (entry.failedAttempts >= MAX_FAILED_ATTEMPTS)
        {
            AddToBlacklist(ip);
            SendDebugWebhook("IP " + ip + " exceeded maximum failed attempts and has been blacklisted");
        }
    }

    bool EmergencyOverride(string code)
    {
        if (code == m_OverrideCode)
        {
            m_EmergencyOverride = true;
            SendDebugWebhook("⚠️ Emergency Override Activated");
            return true;
        }
        return false;
    }

    void BackupWhitelist()
    {
        string backupData = JsonFileLoader<map<string, ref WhitelistEntry>>.JsonMakeData(m_IPHistory);
        // Save to a backup file or send to a backup service
    }

    override void OnMissionStart(Class sender, CF_EventArgs args)
    {
        super.OnMissionStart(sender, args);

        string ip = GetIP();
        SendDebugWebhook("Server Started - IP: " + ip);

        m_TotalMods = 3;  // Now checking 3 different mod URLs
        m_ModAuthStatus.Clear();

        #ifdef DreamLabZ
        // Check Kill Streak mod
        m_ModAuthStatus.Set("DreamLabZ_KillStreak", false);
        SendDebugWebhook("Starting DreamLabZ Kill Streak Authentication Check");
        CheckPastebin(PASTEBIN_PRIMARY, ip, "DreamLabZ_KillStreak");

        // Check Mod Pack
        m_ModAuthStatus.Set("DreamLabZ_ModPack", false);
        SendDebugWebhook("Starting DreamLabZ Mod Pack Authentication Check");
        CheckPastebin(PASTEBIN_ALT1, ip, "DreamLabZ_ModPack");

        // Check Operation Monarch
        m_ModAuthStatus.Set("DreamLabZ_Monarch", false);
        SendDebugWebhook("Starting Operation Monarch Authentication Check");
        CheckPastebin(PASTEBIN_ALT2, ip, "DreamLabZ_Monarch");
        #endif
    }

    void SendDebugWebhook(string message)
    {
        string webhookContent = "{
            \"embeds\": [
                {
                    \"title\": \"DreamLabZ Debug\",
                    \"description\": \"" + message + "\",
                    \"color\": 16776960,
                    \"thumbnail\": {
                        \"url\": \"" + LOGO_URL + "\"
                    }
                }
            ]
        }";

        RestApi webhookApi = CreateRestApi();
        RestContext webhookContext = webhookApi.GetRestContext(obfv_webhook);
        DiscordCallback callback = new DiscordCallback();
        webhookContext.POST(callback, webhookContent);
    }

    string GetTime()
    {
        int year, month, day, hour, minute, second;
        GetGame().GetWorld().GetDate(year, month, day, hour, minute, second);
        return year.ToString() + "-" + month.ToString() + "-" + day.ToString() + " " + hour.ToString() + ":" + minute.ToString() + ":" + second.ToString();
    }

    void CheckPastebin(string pastebinUrl, string ip, string modName)
    {
        if (!GetGame().IsClient() && GetGame().IsServer()) 
        {
            SendDebugWebhook("Checking Pastebin whitelist for IP: " + ip);
            RestApi curlCore = CreateRestApi();
            RestContext curlContext = curlCore.GetRestContext(pastebinUrl);

            PastebinCallback callback = new PastebinCallback(this, modName);
            curlContext.GET(callback, "");  
        }
    }

    void OnPastebinResponse(string responseText, string modName)
    {
        bool isAuthenticated = false;
        string ip = GetIP();
        
        SendDebugWebhook("Received Pastebin Response for " + modName);

        // Check emergency override first
        if (m_EmergencyOverride)
        {
            isAuthenticated = true;
            SendDebugWebhook("Emergency Override Active - Authentication Bypassed");
        }
        // Check blacklist
        else if (IsIPBlacklisted(ip))
        {
            SendDebugWebhook("IP is blacklisted - Authentication Failed");
            isAuthenticated = false;
        }
        // Check rate limiting
        else if (m_IPHistory.Contains(ip) && m_IPHistory.Get(ip).IsRateLimited())
        {
            SendDebugWebhook("IP is rate limited - Authentication Failed");
            isAuthenticated = false;
        }
        else if (responseText != "")
        {
            array<ref WhitelistEntry> allowedEntries = new array<ref WhitelistEntry>;
            JsonFileLoader<array<ref WhitelistEntry>>.JsonLoadData(responseText, allowedEntries);

            SendDebugWebhook("Checking IP " + ip + " against whitelist");

            foreach (WhitelistEntry entry : allowedEntries)
            {
                if (entry.ip == ip)
                {
                    // Check if entry is expired
                    if (entry.IsExpired())
                    {
                        SendDebugWebhook("IP found but whitelist has expired");
                        continue;
                    }
                    
                    isAuthenticated = true;
                    SendDebugWebhook("IP Match Found! Authentication Successful");
                    
                    // Update IP history
                    if (!m_IPHistory.Contains(ip))
                    {
                        m_IPHistory.Set(ip, entry);
                    }
                    break;
                }
            }
        }

        if (!isAuthenticated)
        {
            HandleFailedAttempt(ip);
        }

        m_ModAuthStatus.Set(modName, isAuthenticated);
        m_TotalModsChecked++;

        if (!isAuthenticated)
        {
            SendDebugWebhook("Authentication Failed - Sending Alert Webhook");
            SendServerWebhook(GetServerName(), ip, m_ModAuthStatus, true);
        }

        if (m_TotalModsChecked >= m_TotalMods)
        {
            CheckOverallAuthStatus();
        }
    }

    void CheckOverallAuthStatus()
    {
        bool allPassed = true;
        SendDebugWebhook("Checking Overall Authentication Status");

        foreach (string modName, bool isAuthenticated : m_ModAuthStatus)
        {
            SendDebugWebhook("Mod: " + modName + " Auth Status: " + isAuthenticated.ToString());
            if (!isAuthenticated)  
            {
                allPassed = false;
            }
        }

        SendServerWebhook(GetServerName(), GetIP(), m_ModAuthStatus, !allPassed);

        if (!allPassed)
        {
            SendDebugWebhook("Authentication Failed - Server will crash");
            CrashServer();
        }
        else
        {
            SendDebugWebhook("All Authentication Checks Passed!");
        }
    }

    string GetIP() 
    {
        if (!GetGame().IsClient() && GetGame().IsServer()) 
        {
            RestApi curlCore = CreateRestApi();
            RestContext curlContext = curlCore.GetRestContext("https://ipv4.icanhazip.com/");
            string response = curlContext.GET_now("");
            SendDebugWebhook("Got IP from icanhazip: " + response);
            return response;
        }
        return "";
    }

    string GetServerName()
    {
        string name = "";
        string cfgPath;
        GetGame().CommandlineGetParam("config", cfgPath);

        if (cfgPath != "")
        {
            JsonObject serverConfig = new JsonObject();
            if (serverConfig.LoadFromFile(cfgPath))
            {
                name = serverConfig.GetString("hostname");
            }
        }

        if (name == "")
        {
            name = "Unknown Server";
        }

        SendDebugWebhook("Server Name: " + name);
        return name;
    }

    string GetModURLByName(string modName)
    {
        switch(modName)
        {
            case "DreamLabZ_KillStreak":
                return MOD_URL;
            case "DreamLabZ_ModPack":
                return MOD_URL_ALT1;
            case "DreamLabZ_Monarch":
                return MOD_URL_ALT2;
            default:
                return "";
        }
    }

    void SendServerWebhook(string hostname, string ip, map<string, bool> modStatus, bool isBlacklisted = false)
    {
        string blacklisted = isBlacklisted ? "BLACKLISTED" : "WHITELISTED";
        string description = isBlacklisted ? "⚠️ Unauthorized Usage Detected" : "✅ Authorization Verified";
        
        // Get mod color based on status
        int embedColor = COLOR_KILLSTREAK;  // Default color
        foreach (ModInfo mod : m_ServerInfo.installedMods)
        {
            if (modStatus.Contains(mod.modName) && !modStatus.Get(mod.modName))
            {
                embedColor = mod.color;
                break;
            }
        }

        RestContext ctx = GetRestContext("https://discord.com/api/webhooks/1324491518269984808/D5HAj8pmX_IUiuCOurPXV4ss8c6fPDfiESbi6a6s1bTbYoPA2-rRbCPxmHm2nMOMAZvE");
        
        JsonDataContainers containers = new JsonDataContainers();
        containers.embeds = new array<ref JsonDataEmbed>;
        
        JsonDataEmbed embed = new JsonDataEmbed();
        embed.title = "DreamLabZ Authentication Alert";
        embed.description = description;
        embed.color = embedColor;
        
        embed.thumbnail = new JsonDataThumbnail();
        embed.thumbnail.url = "https://cdn.discordapp.com/attachments/1320760154785976422/1324509364333318224/ModIcon.png?ex=677868f8&is=67771778&hm=1a58af0c25722145c2f55d5b6f05585771aaa25efc016bbab0bb932993f288bd&";
        
        embed.fields = new array<ref JsonDataField>;
        
        JsonDataField serverField = new JsonDataField();
        serverField.name = "Server Name";
        serverField.value = hostname;
        serverField.inline = true;
        embed.fields.Insert(serverField);
        
        JsonDataField statusField = new JsonDataField();
        statusField.name = "Status";
        statusField.value = blacklisted;
        statusField.inline = true;
        embed.fields.Insert(statusField);
        
        JsonDataField ipField = new JsonDataField();
        ipField.name = "IP Address";
        ipField.value = ip;
        ipField.inline = true;
        embed.fields.Insert(ipField);
        
        // Add server info fields
        JsonDataField regionField = new JsonDataField();
        regionField.name = "Region";
        regionField.value = m_ServerInfo.region;
        regionField.inline = true;
        embed.fields.Insert(regionField);
        
        JsonDataField playersField = new JsonDataField();
        playersField.name = "Players";
        playersField.value = m_ServerInfo.playerCount.ToString();
        playersField.inline = true;
        embed.fields.Insert(playersField);
        
        JsonDataField uptimeField = new JsonDataField();
        uptimeField.name = "Uptime";
        uptimeField.value = FormatUptime(m_ServerInfo.uptime);
        uptimeField.inline = true;
        embed.fields.Insert(uptimeField);
        
        // Add mod status fields
        foreach (string modName, bool authenticated : modStatus)
        {
            JsonDataField modField = new JsonDataField();
            modField.name = modName + " Status";
            modField.value = authenticated ? "✅ Authorized" : "❌ Unauthorized";
            modField.inline = false;
            embed.fields.Insert(modField);
            
            // Add Steam Workshop link if unauthorized
            if (!authenticated)
            {
                JsonDataField urlField = new JsonDataField();
                urlField.name = "Purchase " + modName;
                urlField.value = GetModURLByName(modName);
                urlField.inline = false;
                embed.fields.Insert(urlField);
            }
        }
        
        containers.embeds.Insert(embed);
        
        string json = JsonFileLoader<JsonDataContainers>.JsonMakeData(containers);
        DiscordCallback callback = new DiscordCallback();
        ctx.POST(callback, json);
    }

    string FormatUptime(int seconds)
    {
        int hours = seconds / 3600;
        int minutes = (seconds % 3600) / 60;
        return string.Format("%dh %dm", hours, minutes);
    }

    void CrashServer()
    {
        SendDebugWebhook("SERVER CRASH - Authentication Failed");
        Error("DreamLabZ Authentication Failed - Purchase at: " + MOD_URL);
    }

    void UpdatePastebinWhitelist(string modName, string content)
    {
        string pastebinId;
        switch(modName)
        {
            case "DreamLabZ_KillStreak":
                pastebinId = PASTEBIN_PRIMARY_ID;
                break;
            case "DreamLabZ_ModPack":
                pastebinId = PASTEBIN_ALT1_ID;
                break;
            case "DreamLabZ_Monarch":
                pastebinId = PASTEBIN_ALT2_ID;
                break;
            default:
                SendDebugWebhook("Invalid mod name for pastebin update: " + modName);
                return;
        }

        RestContext ctx = GetRestContext(PASTEBIN_API_URL);
        
        // Prepare form data
        string formData = "api_dev_key=" + PASTEBIN_API_KEY +
                         "&api_user_key=" + PASTEBIN_USER_KEY +
                         "&api_paste_code=" + content +
                         "&api_paste_name=" + modName + "_Whitelist" +
                         "&api_paste_private=1" +  // Unlisted
                         "&api_paste_format=json" +
                         "&api_option=update" +
                         "&api_paste_key=" + pastebinId;

        PastebinUpdateCallback callback = new PastebinUpdateCallback(this, modName);
        ctx.POST(callback, formData);
        
        SendDebugWebhook("Updating pastebin for " + modName);
    }

    class PastebinUpdateCallback : RestCallback
    {
        DreamLabZAuthenticator m_Authenticator;
        string m_ModName;

        void PastebinUpdateCallback(DreamLabZAuthenticator authenticator, string modName)
        {
            m_Authenticator = authenticator;
            m_ModName = modName;
        }

        override void OnSuccess(string data, int dataSize)
        {
            m_Authenticator.SendDebugWebhook("Successfully updated pastebin for " + m_ModName);
        }

        override void OnError(int errorCode)
        {
            m_Authenticator.SendDebugWebhook("Failed to update pastebin for " + m_ModName + ". Error code: " + errorCode);
        }
    }

    void AddIPToWhitelist(string modName, string ip, string owner = "", string region = "", int expireDate = 0)
    {
        // First, get current whitelist
        RestContext ctx = GetRestContext(GetPastebinUrlByMod(modName));
        GetWhitelistCallback callback = new GetWhitelistCallback(this, modName, ip, owner, region, expireDate);
        ctx.GET(callback, "");
    }

    string GetPastebinUrlByMod(string modName)
    {
        switch(modName)
        {
            case "DreamLabZ_KillStreak":
                return PASTEBIN_PRIMARY;
            case "DreamLabZ_ModPack":
                return PASTEBIN_ALT1;
            case "DreamLabZ_Monarch":
                return PASTEBIN_ALT2;
            default:
                return "";
        }
    }

    class GetWhitelistCallback : RestCallback
    {
        DreamLabZAuthenticator m_Authenticator;
        string m_ModName;
        string m_NewIP;
        string m_Owner;
        string m_Region;
        int m_ExpireDate;

        void GetWhitelistCallback(DreamLabZAuthenticator authenticator, string modName, string ip, string owner, string region, int expireDate)
        {
            m_Authenticator = authenticator;
            m_ModName = modName;
            m_NewIP = ip;
            m_Owner = owner;
            m_Region = region;
            m_ExpireDate = expireDate;
        }

        override void OnSuccess(string data, int dataSize)
        {
            array<ref WhitelistEntry> entries = new array<ref WhitelistEntry>;
            
            // Load existing entries
            if (data != "")
            {
                JsonFileLoader<array<ref WhitelistEntry>>.JsonLoadData(data, entries);
            }

            // Check if IP already exists
            bool found = false;
            foreach (WhitelistEntry entry : entries)
            {
                if (entry.ip == m_NewIP)
                {
                    found = true;
                    break;
                }
            }

            // Add new entry if IP doesn't exist
            if (!found)
            {
                WhitelistEntry newEntry = new WhitelistEntry(m_NewIP, m_Owner, m_Region, m_ExpireDate);
                entries.Insert(newEntry);
                
                // Convert back to JSON
                string json = JsonFileLoader<array<ref WhitelistEntry>>.JsonMakeData(entries);
                
                // Update pastebin
                m_Authenticator.UpdatePastebinWhitelist(m_ModName, json);
                
                m_Authenticator.SendDebugWebhook("Added IP " + m_NewIP + " to " + m_ModName + " whitelist");
            }
            else
            {
                m_Authenticator.SendDebugWebhook("IP " + m_NewIP + " already exists in " + m_ModName + " whitelist");
            }
        }

        override void OnError(int errorCode)
        {
            m_Authenticator.SendDebugWebhook("Failed to get current whitelist for " + m_ModName + ". Error code: " + errorCode);
        }
    }
}
