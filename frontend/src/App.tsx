import React from 'react';
import Navbar from './components/Navbar';
import HeroSection from './components/HeroSection';
import AboutSection from './components/AboutSection';
import FeaturesSection from './components/FeaturesSection';
import HowItWorksSection from './components/HowItWorksSection';
import ArchitectureSection from './components/ArchitectureSection';
import DatasetSection from './components/DatasetSection';
import DemoSection from './components/DemoSection';
import DashboardSection from './components/DashboardSection';
import ResearchSection from './components/ResearchSection';
import TechStackSection from './components/TechStackSection';
import TeamSection from './components/TeamSection';
import Footer from './components/Footer';

function App() {
    return (
        <div
            className="min-h-screen text-white font-sans overflow-x-hidden"
            style={{ background: '#060B18' }}
        >
            <Navbar />
            <main>
                {/* 1. Hero — animated particle background + headline */}
                <HeroSection />

                {/* 2. About — the zero-day problem */}
                <AboutSection />

                {/* 3. Features — 6 capability cards */}
                <FeaturesSection />

                {/* 4. How It Works — CNN–BiLSTM pipeline flowchart */}
                <HowItWorksSection />

                {/* 5. Architecture — layer-by-layer deep learning pipeline */}
                <ArchitectureSection />

                {/* 6. Training & Performance — charts + metrics */}
                <DatasetSection />

                {/* 7. Live URL Detection Demo */}
                <DemoSection />

                {/* 8. Dashboard — stats, donut chart, scan history, model perf */}
                <DashboardSection />

                {/* 9. Research Contributions */}
                <ResearchSection />

                {/* 10. Tech Stack */}
                <TechStackSection />

                {/* 11. Academic Presentation info */}
                <TeamSection />
            </main>
            <Footer />
        </div>
    );
}

export default App;
