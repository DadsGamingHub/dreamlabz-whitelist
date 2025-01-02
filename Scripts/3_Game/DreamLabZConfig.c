class DreamLabZConfig
{
    protected static const string PROFILE_FOLDER = "$profile:DreamLabZ";
    
    void DreamLabZConfig()
    {
        // Create the mod's profile directory if it doesn't exist
        if (!FileExist(PROFILE_FOLDER))
        {
            MakeDirectory(PROFILE_FOLDER);
            Print("[DreamLabZ] Created profile directory: " + PROFILE_FOLDER);
        }
    }

    static string GetProfileFolder()
    {
        return PROFILE_FOLDER;
    }
}
