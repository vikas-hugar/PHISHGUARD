import React, { lazy, Suspense, useState } from "react";
import PhishGuardLanding from "./components/PhishGuardLanding";
import type { DashboardTab } from "./components/PhishGuardDashboard";

const PhishGuardDashboard = lazy(() => import("./components/PhishGuardDashboard"));

export default function App() {
  const [currentView, setCurrentView] = useState<"landing" | "dashboard">("landing");
  const [initialDashboardTab, setInitialDashboardTab] = useState<DashboardTab>("overview");

  const handleLaunchScanner = () => {
    setInitialDashboardTab("scanner");
    setCurrentView("dashboard");
    window.scrollTo({ top: 0, behavior: "instant" });
  };

  const handleOpenDashboard = (tab: DashboardTab = "overview") => {
    setInitialDashboardTab(tab);
    setCurrentView("dashboard");
    window.scrollTo({ top: 0, behavior: "instant" });
  };

  const handleBackToLanding = () => {
    setCurrentView("landing");
    window.scrollTo({ top: 0, behavior: "instant" });
  };

  return (
    <div className="min-h-screen bg-[#000000] text-[#FFFFFF] font-sans selection:bg-[#FFFFFF] selection:text-[#000000]">
      {currentView === "landing" ? (
        <PhishGuardLanding
          onLaunchScanner={handleLaunchScanner}
          onExploreCapabilities={() => {}}
        />
      ) : (
        <Suspense fallback={<p role="status" className="p-6">Loading dashboard?</p>}>
          <PhishGuardDashboard
            onBackToLanding={handleBackToLanding}
            initialTab={initialDashboardTab}
          />
        </Suspense>
      )}
    </div>
  );
}
