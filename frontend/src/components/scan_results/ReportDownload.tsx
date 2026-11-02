import React from 'react';
import { Download, FileText } from 'lucide-react';

interface ReportDownloadProps {
    onDownload: () => void;
}

export const ReportDownload: React.FC<ReportDownloadProps> = ({ onDownload }) => {
    return (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-800 text-slate-300 flex items-center justify-center shrink-0">
                    <FileText className="w-4 h-4" />
                </div>
                <div>
                    <h4 className="text-xs font-semibold text-slate-200">Security Audit Report</h4>
                    <p className="text-[11px] text-slate-400">Export clean forensic summary and telemetry in PDF format</p>
                </div>
            </div>

            <button
                type="button"
                onClick={onDownload}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors cursor-pointer"
            >
                <Download className="w-3.5 h-3.5 text-slate-300" />
                <span>Download PDF Report</span>
            </button>
        </div>
    );
};
