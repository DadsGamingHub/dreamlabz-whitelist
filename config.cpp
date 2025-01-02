class CfgPatches
{
	class DreamLabZ
	{
		units[] = {};
		weapons[] = {};
		requiredVersion = 0.1;
		requiredAddons[] = {"DZ_Data", "DZ_Scripts"};
	};
};

class CfgMods
{
	class DreamLabZ
	{
		dir = "DreamLabZ";
		picture = "";
		action = "";
		hideName = 1;
		hidePicture = 1;
		name = "DreamLabZ";
		credits = "DreamLabZ";
		author = "DreamLabZ";
		authorID = "0";
		version = 1.0;
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
					"DreamLabZ/Scripts/3_Game/DreamLabZConfig"
				};
			};
			class worldScriptModule
			{
				value = "";
				files[] = {
					"DreamLabZ/Scripts/4_World"
				};
			};
			class missionScriptModule
			{
				value = "";
				files[] = {
					"DreamLabZ/Scripts/5_Mission"
				};
			};
		};
	};
};
