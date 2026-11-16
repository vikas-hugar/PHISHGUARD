import React, { useState } from "react";
import PhishGuardLanding from "./components/PhishGuardLanding";
import PhishGuardDashboard, { DashboardTab } from "./components/PhishGuardDashboard";

export default function App() {
  const [currentView, setCurrentView] = useState<"landing" | "dashboard">("landing");
  const [initialDashboardTab, setInitialDashboardTab] = useState<DashboardTab>("overview");

  const handleLaunchScanner = () => {
    setInitialDashboardTab("scanner");
    setCurrentView("dashboard");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleOpenDashboard = (tab: DashboardTab = "overview") => {
    setInitialDashboardTab(tab);
    setCurrentView("dashboard");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleBackToLanding = () => {
    setCurrentView("landing");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="min-h-screen bg-[#000000] text-[#FFFFFF] font-sans selection:bg-[#FFFFFF] selection:text-[#000000]">
      {currentView === "landing" ? (
        <PhishGuardLanding
          onLaunchScanner={handleLaunchScanner}
          onExploreCapabilities={() => {}}
        />
      ) : (
        <PhishGuardDashboard
          onBackToLanding={handleBackToLanding}
          initialTab={initialDashboardTab}
        />
      )}
    </div>
  );
}
