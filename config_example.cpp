class CfgPatches
{
    class DreamLabZ // Replace with your mod name
    {
        units[] = {};
        weapons[] = {};
        requiredVersion = 0.1;
        requiredAddons[] = {"DZ_Data", "DZ_Scripts"}; // Add any other required addons here
    };
};

class CfgMods
{
    class DreamLabZ // Replace with your mod name (same as above)
    {
        dir = "DreamLabZ";          // Your mod folder name
        picture = "";                   // Path to picture (optional)
        action = "";                    // Action string (optional)
        hideName = 1;                   // Hide the mod name
        hidePicture = 1;               // Hide the mod picture
        name = "DreamLabZ";         // Display name of your mod
        credits = "DreamLabZ";          // Credits
        author = "DreamLabZ";           // Author name
        authorID = "0";                 // Your Steam ID or other identifier
        version = "1.0";               // Your mod version
        extra = 0;
        type = "mod";
        
        dependencies[] = 
        {
            "Game",
            "World",
            "Mission"
        };

        class defs
        {
            class gameScriptModule
            {
                value = "";
                files[] = {
                    "DreamLabZ/Scripts/3_Game"    // Game scripts path
                };
            };
            
            class worldScriptModule
            {
                value = "";
                files[] = {
                    "DreamLabZ/Scripts/4_World"   // World scripts path
                };
            };
            
            class missionScriptModule
            {
                value = "";
                files[] = {
                    "DreamLabZ/Scripts/5_Mission" // Mission scripts path
                };
            };
        };
    };
};
