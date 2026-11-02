import React, { useState } from 'react';
import {
    ChevronDown, ChevronUp, Cpu, Shield, Globe, Eye, Activity, Clock,
    CheckCircle2, AlertTriangle, AlertCircle, Info, Layers, Terminal
} from 'lucide-react';
import { PredictionResponse } from '../DemoSection';

interface TechnicalDetailsProps {
    result: PredictionResponse;
}

export const TechnicalDetails: React.FC<TechnicalDetailsProps> = ({ result }) => {
    const [isExpanded, setIsExpanded] = useState(false);
    const [activeTab, setActiveTab] = useState<'models' | 'domain' | 'behavior' | 'visual' | 'timings'>('models');

    // Extract relevant data safely
    const cnn = result.models?.cnn_bilstm || result.cnn;
    const roberta = result.models?.roberta || result.roberta;
    const fusion = result.fusion;
    const domBehavior = result.dom_behavior_analysis || result.signals?.dom_behavior;
    const visual = result.visual_analysis;
    const timing = result.timing;
    const deepScan = result.deep_scan;
    const ocrWordCount = result.ocr?.word_count ?? deepScan?.ocr_word_count ?? result.signals?.screenshot?.ocr_word_count ?? 0;
    const ocrExtractedText = result.ocr?.text || result.signals?.screenshot?.ocr_text || result.signals?.screenshot?.visual_text_preview;
    const ocrBrandCandidates = result.ocr?.brand_candidates || result.signals?.screenshot?.brand_candidates || [];

    return (
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
            {/* Header Accordion Toggle */}
            <button
                type="button"
                onClick={() => setIsExpanded(!isExpanded)}
                className="w-full p-5 sm:p-6 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors cursor-pointer"
            >
                <div className="space-y-1">
                    <div className="flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-slate-400" />
                        <h3 className="text-base font-semibold text-slate-100">Technical Analysis</h3>
                        <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            Advanced Telemetry
                        </span>
                    </div>
                    <p className="text-xs text-slate-400">
                        Detailed model scores, behavioral telemetry, visual OCR, and latency timings
                    </p>
                </div>
                <div className="flex items-center gap-2 text-xs font-medium text-slate-400">
                    <span>{isExpanded ? 'Hide technical details' : 'Show technical details'}</span>
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </div>
            </button>

            {/* Expanded Content */}
            {isExpanded && (
                <div className="border-t border-slate-800 p-5 sm:p-6 space-y-6 bg-slate-950/40">
                    {/* Navigation Tabs */}
                    <div className="flex flex-wrap gap-1 border-b border-slate-800 pb-2">
                        <button
                            type="button"
                            onClick={() => setActiveTab('models')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                                activeTab === 'models'
                                    ? 'bg-slate-800 text-slate-100 border border-slate-700'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            Detection Models
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('domain')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                                activeTab === 'domain'
                                    ? 'bg-slate-800 text-slate-100 border border-slate-700'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            Domain &amp; Threat Intelligence
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('behavior')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                                activeTab === 'behavior'
                                    ? 'bg-slate-800 text-slate-100 border border-slate-700'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            Website Behavior
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('visual')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                                activeTab === 'visual'
                                    ? 'bg-slate-800 text-slate-100 border border-slate-700'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            Visual &amp; Text Analysis
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('timings')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                                activeTab === 'timings'
                                    ? 'bg-slate-800 text-slate-100 border border-slate-700'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            Execution Timings
                        </button>
                    </div>

                    {/* Tab 1: Detection Models */}
                    {activeTab === 'models' && (
                        <div className="space-y-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {/* Pattern-based URL analysis (CNN-BiLSTM) */}
                                <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                            <Cpu className="w-4 h-4 text-slate-400" />
                                            <span className="text-xs font-semibold text-slate-200">
                                                Pattern-based URL analysis (CNN-BiLSTM)
                                            </span>
                                        </div>
                                        <span className={`text-[10px] px-2 py-0.5 rounded font-medium border ${
                                            cnn?.executed
                                                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                                : 'bg-slate-800 text-slate-400 border-slate-700'
                                        }`}>
                                            {cnn?.executed ? 'Executed' : 'Unavailable'}
                                        </span>
                                    </div>
                                    <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800 text-xs">
                                        <div>
                                            <span className="text-slate-400 block text-[11px]">Raw Probability</span>
                                            <span className="font-mono text-slate-200">
                                                {cnn?.raw_probability != null ? `${cnn.raw_probability}%` : result.cnn_score != null ? `${result.cnn_score}%` : 'N/A'}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="text-slate-400 block text-[11px]">Calibrated</span>
                                            <span className="font-mono text-slate-200">
                                                {cnn?.calibrated_probability != null ? `${cnn.calibrated_probability}%` : result.cnn_score != null ? `${result.cnn_score}%` : 'N/A'}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="text-slate-400 block text-[11px]">Latency</span>
                                            <span className="font-mono text-slate-200">
                                                {cnn?.latency_ms ?? timing?.cnn_ms ?? 0} ms
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                {/* Language-based URL analysis (RoBERTa) */}
                                <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                            <Cpu className="w-4 h-4 text-slate-400" />
                                            <span className="text-xs font-semibold text-slate-200">
                                                Language-based URL analysis (RoBERTa)
                                            </span>
                                        </div>
                                        <span className={`text-[10px] px-2 py-0.5 rounded font-medium border ${
                                            roberta?.executed
                                                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                                : 'bg-slate-800 text-slate-400 border-slate-700'
                                        }`}>
                                            {roberta?.executed ? 'Executed' : 'Unavailable'}
                                        </span>
                                    </div>
                                    <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800 text-xs">
                                        <div>
                                            <span className="text-slate-400 block text-[11px]">Raw Probability</span>
                                            <span className="font-mono text-slate-200">
                                                {roberta?.raw_probability != null ? `${roberta.raw_probability}%` : result.roberta_score != null ? `${result.roberta_score}%` : 'N/A'}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="text-slate-400 block text-[11px]">Calibrated</span>
                                            <span className="font-mono text-slate-200">
                                                {roberta?.calibrated_probability != null ? `${roberta.calibrated_probability}%` : result.roberta_score != null ? `${result.roberta_score}%` : 'N/A'}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="text-slate-400 block text-[11px]">Latency</span>
                                            <span className="font-mono text-slate-200">
                                                {roberta?.latency_ms ?? timing?.roberta_ms ?? 0} ms
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Consensus & Evidence */}
                            <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-300">
                                <div>
                                    <span className="text-slate-400 mr-1">Detection consistency:</span>
                                    <span className="font-medium text-slate-100">
                                        {fusion?.model_agreement_level || (result.model_disagreement ? 'Disagreement' : 'Consistent')}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-slate-400 mr-1">Consensus:</span>
                                    <span className="font-medium text-slate-100">{result.neural_consensus || 'Standard'}</span>
                                </div>
                                <div>
                                    <span className="text-slate-400 mr-1">Evidence vectors:</span>
                                    <span className="font-medium text-slate-100">
                                        {fusion?.evidence_count ?? result.evidence_count ?? 1} analyzed
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Tab 2: Domain & Threat Intelligence */}
                    {activeTab === 'domain' && (
                        <div className="space-y-3">
                            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Known threats</span>
                                    <span className={`font-semibold ${result.repository_status === 'Found' ? 'text-red-400' : 'text-emerald-400'}`}>
                                        {result.repository_status === 'Found' ? 'Malicious match found' : 'No known match'}
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Look-alike characters</span>
                                    <span className={`font-semibold ${result.homoglyph_analysis?.detected ? 'text-amber-400' : 'text-emerald-400'}`}>
                                        {result.homoglyph_analysis?.detected ? 'Detected' : 'None'}
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Domain character check</span>
                                    <span className={`font-semibold ${result.punycode_analysis?.is_punycode ? 'text-amber-400' : 'text-emerald-400'}`}>
                                        {result.punycode_analysis?.is_punycode ? 'Punycode active' : 'Standard ASCII'}
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Similar domain check</span>
                                    <span className={`font-semibold ${result.typosquatting_analysis?.is_typosquat ? 'text-amber-400' : 'text-emerald-400'}`}>
                                        {result.typosquatting_analysis?.is_typosquat ? 'Potential typo-squat' : 'Clean'}
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Brand impersonation check</span>
                                    <span className={`font-semibold ${result.target_brand && result.target_brand !== 'None' ? 'text-amber-400' : 'text-slate-300'}`}>
                                        {result.target_brand && result.target_brand !== 'None' ? result.target_brand : 'None detected'}
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Third-party websites</span>
                                    <span className="font-semibold text-slate-200">
                                        {deepScan?.failed_resources_count ?? 0} resources checked
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Tab 3: Website Behavior */}
                    {activeTab === 'behavior' && (
                        <div className="space-y-3">
                            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">DOM Mutations</span>
                                    <span className="font-semibold text-slate-200">
                                        {domBehavior?.temporal_analysis?.mutation_count ?? 0} recorded
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Dynamic Password Injection</span>
                                    <span className={`font-semibold ${domBehavior?.temporal_analysis?.dynamic_password_injection ? 'text-red-400' : 'text-emerald-400'}`}>
                                        {domBehavior?.temporal_analysis?.dynamic_password_injection ? 'Detected' : 'None'}
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Deceptive Overlays</span>
                                    <span className={`font-semibold ${domBehavior?.ui_deception?.hidden_overlay_detected ? 'text-amber-400' : 'text-emerald-400'}`}>
                                        {domBehavior?.ui_deception?.hidden_overlay_detected ? 'Detected' : 'None'}
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Anti-Debugging Script</span>
                                    <span className={`font-semibold ${domBehavior?.script_evasion?.anti_debugging_detected ? 'text-amber-400' : 'text-emerald-400'}`}>
                                        {domBehavior?.script_evasion?.anti_debugging_detected ? 'Detected' : 'None'}
                                    </span>
                                </div>
                            </div>

                            {domBehavior?.summary && (
                                <p className="text-xs text-slate-400 bg-slate-900 p-3 rounded-lg border border-slate-800">
                                    {domBehavior.summary}
                                </p>
                            )}
                        </div>
                    )}

                    {/* Tab 4: Visual & Text Analysis */}
                    {activeTab === 'visual' && (
                        <div className="space-y-3">
                            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Visual appearance</span>
                                    <span className={`font-semibold ${visual?.is_login_page ? 'text-amber-400' : 'text-slate-200'}`}>
                                        {visual?.is_login_page ? 'Login layout detected' : 'Standard page'}
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Text detected from images</span>
                                    <span className="font-semibold text-slate-200">
                                        {ocrWordCount} words
                                    </span>
                                </div>
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[11px] mb-1">Brand candidates</span>
                                    <span className="font-semibold text-slate-200">
                                        {ocrBrandCandidates.length > 0 ? ocrBrandCandidates.join(', ') : 'None'}
                                    </span>
                                </div>
                            </div>

                            {ocrExtractedText && (
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-400">
                                    <span className="font-medium text-slate-300 block mb-1">Text extracted:</span>
                                    <p className="font-mono text-[11px] line-clamp-3">{ocrExtractedText}</p>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Tab 5: Execution Timings */}
                    {activeTab === 'timings' && (
                        <div className="space-y-3">
                            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2.5 text-xs">
                                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[10px]">URL Check</span>
                                    <span className="font-mono text-slate-200">{timing?.ssrf_ms ?? 0} ms</span>
                                </div>
                                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[10px]">Known Threats</span>
                                    <span className="font-mono text-slate-200">{timing?.threat_intel_ms ?? 0} ms</span>
                                </div>
                                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[10px]">Pattern Model</span>
                                    <span className="font-mono text-slate-200">{timing?.cnn_ms ?? 0} ms</span>
                                </div>
                                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[10px]">Language Model</span>
                                    <span className="font-mono text-slate-200">{timing?.roberta_ms ?? 0} ms</span>
                                </div>
                                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                                    <span className="text-slate-400 block text-[10px]">Isolated Website Analysis</span>
                                    <span className="font-mono text-slate-200">{timing?.deep_scan_ms ?? 0} ms</span>
                                </div>
                            </div>

                            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between text-xs">
                                <span className="text-slate-400">Total scan latency:</span>
                                <span className="font-semibold text-slate-100 font-mono">{result.detection_time_ms} ms</span>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};
