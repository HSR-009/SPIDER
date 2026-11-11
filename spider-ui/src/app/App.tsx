import { Route, Routes } from "react-router-dom";
import { Workbench, NotFoundPage } from "../components/Workbench";
import { ExperienceOverview } from "../components/overview/ExperienceOverview";
import { ToolHub } from "../components/ToolHub";
import { ExtensionPage, HowPackagesAttackPage } from "../components/ToolPages";
import { ResearchPage } from "../components/ResearchPage";
import {
  ResearchOverview,
  ResearchDataset,
  ResearchSignals,
  ResearchModels,
  ResearchLimits,
} from "../components/ResearchLabPages";
import {
  RedTeamOverview,
  RedTeamBatch,
  RedTeamTechniques,
  RedTeamLimits,
} from "../components/RedTeamPages";
import {
  ScannerScanPage,
  ScannerResultPage,
  ScannerEvidencePage,
  ScannerScorePage,
  ScannerReportPage,
  HunterScanPage,
  HunterReportPage,
  HistoryListPage,
  HistoryReportsPage,
  SettingsPage,
} from "../components/WorkbenchPages";

export default function App() {
  return (
    <Workbench>
      <Routes>
        {/* Welcome */}
        <Route path="/" element={<ExperienceOverview />} />

        {/* Hub */}
        <Route path="/hub" element={<ToolHub />} />

        {/* Package Scanner */}
        <Route path="/scanner/scan" element={<ScannerScanPage />} />
        <Route path="/scanner/result" element={<ScannerResultPage />} />
        <Route path="/scanner/evidence" element={<ScannerEvidencePage />} />
        <Route path="/scanner/score" element={<ScannerScorePage />} />
        <Route path="/scanner/report" element={<ScannerReportPage />} />

        {/* Environment Hunter */}
        <Route path="/hunter/scan" element={<HunterScanPage />} />
        <Route path="/hunter/report" element={<HunterReportPage />} />

        {/* Standalone Tools & Guides */}
        <Route path="/extension" element={<ExtensionPage />} />
        <Route path="/learn" element={<HowPackagesAttackPage />} />

        {/* History and Reports */}
        <Route path="/history/history" element={<HistoryListPage />} />
        <Route path="/history/reports" element={<HistoryReportsPage />} />

        {/* Research Results & Research Lab */}
        <Route path="/research" element={<ResearchPage />} />
        <Route path="/research/overview" element={<ResearchOverview />} />
        <Route path="/research/dataset" element={<ResearchDataset />} />
        <Route path="/research/signals" element={<ResearchSignals />} />
        <Route path="/research/models" element={<ResearchModels />} />
        <Route path="/research/limits" element={<ResearchLimits />} />

        {/* Red Team */}
        <Route path="/redteam/overview" element={<RedTeamOverview />} />
        <Route path="/redteam/batch" element={<RedTeamBatch />} />
        <Route path="/redteam/techniques" element={<RedTeamTechniques />} />
        <Route path="/redteam/limits" element={<RedTeamLimits />} />

        {/* Settings */}
        <Route path="/settings" element={<SettingsPage />} />

        {/* Fallback 404 */}
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Workbench>
  );
}
