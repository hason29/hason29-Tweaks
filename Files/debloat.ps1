$ErrorActionPreference = 'silentlycontinue'
	$Bloatware = @(
		#Unnecessary Windows 10 AppX Apps
		"Microsoft.3DBuilder"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.AppConnector"
		"Microsoft.BingFinance"
		"Microsoft.BingNews"
		"Microsoft.BingSports"
		"Microsoft.BingTranslator"
		"Microsoft.3DBuilder" # 3D Builder
		"Microsoft.Appconnector"
		"Microsoft.BingFinance" # Finance
		"Microsoft.BingFoodAndDrink" # Food And Drink
		"Microsoft.BingHealthAndFitness" # Health And Fitness
		"Microsoft.BingNews" # News
		"2FE3CB00.PicsArt-PhotoStudio"
		"46928bounde.EclipseManager"
		"Microsoft.BingFoodAndDrink"
		"Microsoft.BingHealthAndFitness"
		"Microsoft.BingTravel"
		"Microsoft.WindowsReadingList"
		
		# Redstone 5 apps
		"Microsoft.MixedReality.Portal"
		"Microsoft.ScreenSketch"
		"Microsoft.XboxGamingOverlay"
		"Microsoft.YourPhone"
		
		# non-Microsoft
		"2FE3CB00.PicsArt-PhotoStudio"
		"46928bounde.EclipseManager"
		"4DF9E0F8.Netflix"
		"613EBCEA.PolarrPhotoEditorAcademicEdition"
		"6Wunderkinder.Wunderlist"
		"7EE7776C.LinkedInforWindows"
		"89006A2E.AutodeskSketchBook"
		"9E2F88E3.Twitter"
		"A278AB0D.DisneyMagicKingdoms"
		"A278AB0D.MarchofEmpires"
		"ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
		"CAF9E577.Plex"
		"ClearChannelRadioDigital.iHeartRadio"
		"D52A8D61.FarmVille2CountryEscape"
		"D5EA27B7.Duolingo-LearnLanguagesforFree"
		"DB6EA5DB.CyberLinkMediaSuiteEssentials"
		"DolbyLaboratories.DolbyAccess"
		"DolbyLaboratories.DolbyAccess"
		"Drawboard.DrawboardPDF"
		"Facebook.Facebook"
		"Fitbit.FitbitCoach"
		"Flipboard.Flipboard"
		"GAMELOFTSA.Asphalt8Airborne"
		"KeeperSecurityInc.Keeper"
		"NORDCURRENT.COOKINGFEVER"
		"PandoraMediaInc.29680B314EFC2"
		"Playtika.CaesarsSlotsFreeCasino"
		"ShazamEntertainmentLtd.Shazam"
		"SlingTVLLC.SlingTV"
		"SpotifyAB.SpotifyMusic"
		"TheNewYorkTimes.NYTCrossword"
		"ThumbmunkeysLtd.PhototasticCollage"
		"TuneIn.TuneInRadio"
		"WinZipComputing.WinZipUniversal"
		"XINGAG.XING"
		"flaregamesGmbH.RoyalRevolt2"
		"king.com.*"
		"king.com.BubbleWitch3Saga"
		"king.com.CandyCrushSaga"
		"king.com.CandyCrushSodaSaga"
		"4DF9E0F8.Netflix"
		"613EBCEA.PolarrPhotoEditorAcademicEdition"
		"6Wunderkinder.Wunderlist"
		"7EE7776C.LinkedInforWindows"
		"89006A2E.AutodeskSketchBook"
		"9E2F88E3.Twitter"
		"A278AB0D.DisneyMagicKingdoms"
		"A278AB0D.MarchofEmpires"
		"ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
		"CAF9E577.Plex"
		"ClearChannelRadioDigital.iHeartRadio"
		"D52A8D61.FarmVille2CountryEscape"
		"D5EA27B7.Duolingo-LearnLanguagesforFree"
		"DB6EA5DB.CyberLinkMediaSuiteEssentials"
		"DolbyLaboratories.DolbyAccess"
		"DolbyLaboratories.DolbyAccess"
		"Drawboard.DrawboardPDF"
		"Facebook.Facebook"
		"Fitbit.FitbitCoach"
		"Flipboard.Flipboard"
		"GAMELOFTSA.Asphalt8Airborne"
		"KeeperSecurityInc.Keeper"
		"NORDCURRENT.COOKINGFEVER"
		"PandoraMediaInc.29680B314EFC2"
		"Playtika.CaesarsSlotsFreeCasino"
		"ShazamEntertainmentLtd.Shazam"
		"SlingTVLLC.SlingTV"
		"SpotifyAB.SpotifyMusic"
		"TheNewYorkTimes.NYTCrossword"
		"ThumbmunkeysLtd.PhototasticCollage"
		"TuneIn.TuneInRadio"
		"WinZipComputing.WinZipUniversal"
		"XINGAG.XING"
		"flaregamesGmbH.RoyalRevolt2"
		"king.com.*"
		"king.com.BubbleWitch3Saga"
		"king.com.CandyCrushSaga"
		"king.com.CandyCrushSodaSaga"
		"Microsoft.BingSports" # Sports
		"Microsoft.BingTranslator" # Translator
		"Microsoft.BingTravel" # Travel
		"Microsoft.BingWeather" # Weather
		"Microsoft.CommsPhone"
		"Microsoft.ConnectivityStore"
		"Microsoft.GamingServices"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.Messaging"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.MicrosoftPowerBIForWindows"
		"Microsoft.MicrosoftSolitaireCollection" # MS Solitaire
		"Microsoft.MixedReality.Portal"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.Office.OneNote" # MS Office One Note
		"Microsoft.Office.Sway"
		"Microsoft.OneConnect"
		"Microsoft.People" # People
		"Microsoft.MSPaint" # Paint 3D (Where every artist truly start as a kid, i mean, on original Paint, not this 3D)
		"Microsoft.Print3D" # Print 3D
		"Microsoft.SkypeApp" # Skype (Who still uses Skype? Use Discord)
		"Microsoft.Todos" # Microsoft To Do
		"Microsoft.Wallet"
		"Microsoft.Whiteboard" # Microsoft Whiteboard
		"Microsoft.WindowsAlarms" # Alarms
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsMaps" # Maps
		"Microsoft.WindowsPhone"
		"Microsoft.WindowsReadingList"
		"Microsoft.WindowsSoundRecorder"
		"Microsoft.XboxApp" # Xbox Console Companion (Replaced by new App)
		"Microsoft.XboxGameCallableUI"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.YourPhone" # Your Phone
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo" # Movies & TV
		
		# Default Windows 11 apps
		"MicrosoftWindows.Client.WebExperience" # Taskbar Widgets
		"MicrosoftTeams" # Microsoft Teams / Preview
		
		# 3rd party Apps
		"*ACGMediaPlayer*"
		"*ActiproSoftwareLLC*"
		"*AdobePhotoshopExpress*" # Adobe Photoshop Express
		"*Asphalt8Airborne*" # Asphalt 8 Airbone
		"*AutodeskSketchBook*"
		"*BubbleWitch3Saga*" # Bubble Witch 3 Saga
		"*CaesarsSlotsFreeCasino*"
		"*CandyCrush*" # Candy Crush
		"*COOKINGFEVER*"
		"*CyberLinkMediaSuiteEssentials*"
		"*DisneyMagicKingdoms*"
		"*Dolby*" # Dolby Products (Like Atmos)
		"*DrawboardPDF*"
		"*Duolingo-LearnLanguagesforFree*" # Duolingo
		"*EclipseManager*"
		"*Facebook*" # Facebook
		"*FarmVille2CountryEscape*"
		"*FitbitCoach*"
		"*Flipboard*" # Flipboard
		"*HiddenCity*"
		"*Hulu*"
		"*iHeartRadio*"
		"*Keeper*"
		"*LinkedInforWindows*"
		"*MarchofEmpires*"
		"*NYTCrossword*"
		"*OneCalendar*"
		"*PandoraMediaInc*"
		"*PhototasticCollage*"
		"*PicsArt-PhotoStudio*"
		"*Plex*" # Plex
		"*PolarrPhotoEditorAcademicEdition*"
		"*RoyalRevolt*" # Royal Revolt
		"*Shazam*"
		"*SlingTV*"
		"*Speed Test*"
		"*Sway*"
		"*TuneInRadio*"
		"*Twitter*" # Twitter
		"*Viber*"
		"*WinZipUniversal*"
		"*Wunderlist*"
		"*XING*"
		"Microsoft.BingWeather"
		"Microsoft.BingFoodAndDrink"
		"Microsoft.BingHealthAndFitness"
		"Microsoft.BingTravel"
		"Microsoft.MinecraftUWP"
		"Microsoft.GamingServices"
		# "Microsoft.WindowsReadingList"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.Messaging"
		"Microsoft.Advertising.Xaml"
		"Microsoft.FreshPaint" # Paint
		"Microsoft.MicrosoftEdge" # Microsoft Edge
		"Microsoft.MicrosoftStickyNotes" # Sticky Notes
		"Microsoft.WindowsCalculator" # Calculator
		"Microsoft.WindowsCamera" # Camera
		"Microsoft.ScreenSketch" # Snip and Sketch (now called Snipping tool, replaces the Win32 version in clean installs)
		"Microsoft.WindowsFeedbackHub" # Feedback Hub
		"Microsoft.Windows.Photos" # Ph
		"Microsoft.XboxGamingOverlay" # Xbox Game Bar
		"Microsoft.XboxIdentityProvider" # Xbox Identity Provider (Xbox Dependency)
		"Microsoft.Xbox.TCUI" # Xbox Live API communication (Xbox Dependency)
		"*Netflix*" # Netflix
		"*SpotifyMusic*" # Spotify
		"Microsoft.WindowsStore" # Windows Store
		# Apps which cannot be removed using Remove-AppxPackage
		"Microsoft.BioEnrollment"
		"Microsoft.Windows.Cortana" # Cortana
		"Microsoft.WindowsFeedback" # Feedback Module
		"Windows.ContactSupport"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.News"
		"Microsoft.Office.Lens"
		"Microsoft.Office.Sway"
		"Microsoft.Office.OneNote"
		"Microsoft.OneConnect"
		"Microsoft.People"
		"Microsoft.BingNews"
		"Microsoft.BingWeather"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.MicrosoftStickyNotes"
		"Microsoft.People"
		"Microsoft.Todos"
		"Microsoft.Windows.Photos"
		"Microsoft.WindowsAlarms"
		"Microsoft.WindowsCamera"
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsMaps"
		"Microsoft.WindowsSoundRecorder"
		"Microsoft.YourPhone"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
		"MicrosoftTeams"
		"Microsoft.Print3D"
		"Microsoft.SkypeApp"
		"Microsoft.Wallet"
		"Microsoft.Whiteboard"
		"Microsoft.WindowsAlarms"
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsMaps"
		"Microsoft.WindowsPhone"
		"Microsoft.WindowsSoundRecorder"
		"Microsoft.XboxApp"
		"Microsoft.ConnectivityStore"
		"Microsoft.CommsPhone"
		"Microsoft.ScreenSketch"
		"Microsoft.Xbox.TCUI"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxGameCallableUI"
		"Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.MixedReality.Portal"
		"Microsoft.XboxIdentityProvider"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
		"Microsoft.YourPhone"
		"Microsoft.Getstarted"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.XboxGameCallableUI"
		"Microsoft.Windows.PeopleExperienceHost"
		"Microsoft.Windows.ParentalControls"
		"Microsoft.Windows.NarratorQuickStart"
		"Microsoft.MicrosoftEdgeDevToolsClient"
		#Sponsored Windows 10 AppX Apps
		#Add sponsored/featured apps to remove in the "*AppName*" format
		"*EclipseManager*"
		"*ActiproSoftwareLLC*"
		"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
		"*Duolingo-LearnLanguagesforFree*"
		"*PandoraMediaInc*"
		"*CandyCrush*"
		"*BubbleWitch3Saga*"
		"*Wunderlist*"
		"*Flipboard*"
		"*Twitter*"
		"*edge*"
		"*Facebook*"
		"*Royal Revolt*"
		"*Sway*"
		"*Speed Test*"
		"*Dolby*"
		"*Viber*"
		"*ACGMediaPlayer*"
		"*Netflix*"
		"*OneCalendar*"
		"*LinkedInforWindows*"
		"*HiddenCityMysteryofShadows*"
		"*Hulu*"
		"*HiddenCity*"
		"*AdobePhotoshopExpress*"
		"*HotspotShieldFreeVPN*"
		"*Microsoft.Advertising.Xaml*"
		"*Microsoft.MSPaint*"
		"*Microsoft.MicrosoftStickyNotes*"
		"*Microsoft.Windows.Photos*"
		"*Microsoft.WindowsCalculator*"
		"*Microsoft.WindowsStore*"
	)
	Write-Host "Removing Bloatware"
	foreach ($Bloat in $Bloatware)
	{
		Get-AppxPackage -allusers -Name $Bloat | Remove-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
		Write-Host "Removing $Bloat..."
	}
