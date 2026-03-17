"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import ErrorModal from "../components/ErrorModal";
import ConfigModal from "./ConfigModal";
import OutputModal from "./OutputModal";
import LoadPreviousModal from "./LoadPreviousModal";
import { validateUrl } from "../lib/validateUrl";
import type { PayloadEntry as PayloadReconEntry } from "./OutputModal";

const BACKEND = () =>
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
const WS_URL = () => {
  const u = process.env.NEXT_PUBLIC_WS_URL;
  if (u) return u;
  const b = BACKEND();
  if (b.startsWith("https://")) return b.replace("https://", "wss://");
  return b.replace("http://", "ws://");
};

type ToolId = "katana" | "ffuf" | "payload_recon" | "nuclei" | "whatweb" | "subfinder" | "lan";
type JobPhase = "idle" | "starting" | "processing" | "scoring" | "done" | "error";

type KatanaFlagDef = {
  name: string;
  label: string;
  type: "string" | "number" | "boolean";
  default?: unknown;
  multiple?: boolean;
  description?: string;
};
type KatanaFlagsMeta = {
  defaultFlags?: string[];
  flags?: KatanaFlagDef[];
};

type PayloadEntry = {
  found_in: string[];
  action: string;
  method: string;
  query_string: Record<string, string>;
  payload: Record<string, string>;
};

function cn(...xs: (string | false | undefined | null)[]) {
  return xs.filter(Boolean).join(" ");
}

export default function ScanClient() {
  const backend = BACKEND();
  const wsUrl = WS_URL();

  const [targetUrl, setTargetUrl] = useState("http://zero.webappsecurity.com/");
  const [selectedTools, setSelectedTools] = useState<Record<ToolId, boolean>>({
    katana: false,
    ffuf: false,
    payload_recon: false,
    nuclei: false,
    whatweb: false,
    subfinder: false,
    lan: false,
  });

  const [errorModalMessage, setErrorModalMessage] = useState<string | null>(null);

  // Katana config
  const [katanaFlagsMeta, setKatanaFlagsMeta] = useState<KatanaFlagsMeta | null>(null);
  const [katanaEnabled, setKatanaEnabled] = useState<Record<string, boolean>>({});
  const [katanaValues, setKatanaValues] = useState<Record<string, unknown>>({});

  // FFuf config
  const [ffufWordlistMode, setFfufWordlistMode] = useState<"default" | "upload">("default");
  const [ffufUploadedFileId, setFfufUploadedFileId] = useState<string | null>(null);
  const [ffufMc, setFfufMc] = useState("");
  const [ffufFc, setFfufFc] = useState("");
  const [ffufThreads, setFfufThreads] = useState<number | "">("");
  const [ffufRate, setFfufRate] = useState<number | "">("");
  const [ffufExtensions, setFfufExtensions] = useState("");
  const [ffufFollowRedirects, setFfufFollowRedirects] = useState(false);
  const [ffufAutoCalibrate, setFfufAutoCalibrate] = useState(false);
  const ffufFileInputRef = useRef<HTMLInputElement>(null);

  // Subfinder config
  const [subfinderHttpxTimeoutSec, setSubfinderHttpxTimeoutSec] = useState<number | "">(5);

  // Job state
  const [katanaPhase, setKatanaPhase] = useState<JobPhase>("idle");
  const [katanaStatus, setKatanaStatus] = useState("");
  const [katanaJobId, setKatanaJobId] = useState<string | null>(null);
  const [katanaResultFile, setKatanaResultFile] = useState<string | null>(null);
  const [katanaLogs, setKatanaLogs] = useState<string[]>([]);

  const [ffufPhase, setFfufPhase] = useState<JobPhase>("idle");
  const [ffufStatus, setFfufStatus] = useState("");
  const [ffufJobId, setFfufJobId] = useState<string | null>(null);
  const [ffufResultFile, setFfufResultFile] = useState<string | null>(null);
  const [ffufLogs, setFfufLogs] = useState<string[]>([]);

  // Nuclei job state
  const [nucleiPhase, setNucleiPhase] = useState<JobPhase>("idle");
  const [nucleiStatus, setNucleiStatus] = useState("");
  const [nucleiJobId, setNucleiJobId] = useState<string | null>(null);
  const [nucleiResultFile, setNucleiResultFile] = useState<string | null>(null);
  const [nucleiLogs, setNucleiLogs] = useState<string[]>([]);

  // WhatWeb job state
  const [whatwebPhase, setWhatwebPhase] = useState<JobPhase>("idle");
  const [whatwebStatus, setWhatwebStatus] = useState("");
  const [whatwebJobId, setWhatwebJobId] = useState<string | null>(null);
  const [whatwebResultFile, setWhatwebResultFile] = useState<string | null>(null);
  const [whatwebLogs, setWhatwebLogs] = useState<string[]>([]);
  const [whatwebAggression, setWhatwebAggression] = useState<1 | 3 | 4>(1);

  // Subfinder job state
  const [subfinderPhase, setSubfinderPhase] = useState<JobPhase>("idle");
  const [subfinderStatus, setSubfinderStatus] = useState("");
  const [subfinderJobId, setSubfinderJobId] = useState<string | null>(null);
  const [subfinderResultFile, setSubfinderResultFile] = useState<string | null>(null);
  const [subfinderLogs, setSubfinderLogs] = useState<string[]>([]);

  // LAN job state
  const [lanPhase, setLanPhase] = useState<JobPhase>("idle");
  const [lanStatus, setLanStatus] = useState("");
  const [lanJobId, setLanJobId] = useState<string | null>(null);
  const [lanResultFile, setLanResultFile] = useState<string | null>(null);
  const [lanLogs, setLanLogs] = useState<string[]>([]);

  // LAN config
  const [lanCidr, setLanCidr] = useState("192.168.1.0/24");
  const [lanMode, setLanMode] = useState<"fast" | "accurate">("fast");
  const [lanPortsPreset, setLanPortsPreset] = useState<"top100" | "top1000" | "custom">("top100");
  const [lanCustomPorts, setLanCustomPorts] = useState("");

  const [payloadPhase, setPayloadPhase] = useState<"idle" | "running" | "done" | "error">("idle");
  const [payloadEntries, setPayloadEntries] = useState<PayloadEntry[] | null>(null);
  const [payloadResultFile, setPayloadResultFile] = useState<string | null>(null);
  const [payloadReconId, setPayloadReconId] = useState<number | null>(null);

  const [configModalTool, setConfigModalTool] = useState<null | ToolId>(null);
  const [outputModalTool, setOutputModalTool] = useState<null | ToolId>(null);
  const [loadPreviousOpen, setLoadPreviousOpen] = useState(false);

  const katanaWsRef = useRef<WebSocket | null>(null);
  const ffufWsRef = useRef<WebSocket | null>(null);
  const nucleiWsRef = useRef<WebSocket | null>(null);
  const whatwebWsRef = useRef<WebSocket | null>(null);
  const subfinderWsRef = useRef<WebSocket | null>(null);
  const lanWsRef = useRef<WebSocket | null>(null);
  const payloadReconStartedRef = useRef(false);

  const anyRunning =
    katanaPhase === "starting" ||
    katanaPhase === "processing" ||
    katanaPhase === "scoring" ||
    ffufPhase === "starting" ||
    ffufPhase === "processing" ||
    ffufPhase === "scoring" ||
    nucleiPhase === "starting" ||
    nucleiPhase === "processing" ||
    nucleiPhase === "scoring" ||
    whatwebPhase === "starting" ||
    whatwebPhase === "processing" ||
    whatwebPhase === "scoring" ||
    subfinderPhase === "starting" ||
    subfinderPhase === "processing" ||
    subfinderPhase === "scoring" ||
    lanPhase === "starting" ||
    lanPhase === "processing" ||
    lanPhase === "scoring" ||
    payloadPhase === "running";

  useEffect(() => {
    let c = false;
    fetch(`${backend}/api/tools/katana/flags`, { cache: "no-store" })
      .then((r) => r.json())
      .then((data: KatanaFlagsMeta) => {
        if (c) return;
        setKatanaFlagsMeta(data);
        const enabled: Record<string, boolean> = {};
        const values: Record<string, unknown> = {};
        (data.flags || []).forEach((f) => {
          if (f.type === "boolean") {
            enabled[f.name] = f.default === true;
            values[f.name] = f.default;
          } else if (f.type === "number" && f.default !== undefined) {
            enabled[f.name] = true;
            values[f.name] = f.default;
          } else {
            enabled[f.name] = false;
            values[f.name] = f.default ?? "";
          }
        });
        if (values["-depth"] === undefined) {
          enabled["-depth"] = true;
          values["-depth"] = 5;
        }
        setKatanaEnabled(enabled);
        setKatanaValues(values);
      })
      .catch(() => {});
    return () => {
      c = true;
    };
  }, [backend]);

  useEffect(() => {
    return () => {
      katanaWsRef.current?.close();
      ffufWsRef.current?.close();
      nucleiWsRef.current?.close();
      whatwebWsRef.current?.close();
      subfinderWsRef.current?.close();
      lanWsRef.current?.close();
    };
  }, []);

  // Fallback: if nuclei finished but WS "done" was missed (server restart, etc.),
  // periodically check latest nuclei result for this target and update UI to Done.
  useEffect(() => {
    if (!selectedTools.nuclei) return;
    const running =
      nucleiPhase === "starting" || nucleiPhase === "processing" || nucleiPhase === "scoring";
    if (!running) return;
    if (nucleiResultFile) return;

    let cancelled = false;
    const tick = async () => {
      try {
        const norm = normalizeUrlForLookup(targetUrl);
        if (!norm) return;
        const tRes = await fetch(`${backend}/api/targets?q=${encodeURIComponent(norm)}&limit=20`, { cache: "no-store" });
        if (!tRes.ok) return;
        const targets = (await tRes.json()) as { target_id: number; target_name: string }[];
        const exact = (targets || []).find((t) => normalizeUrlForLookup(t.target_name) === norm);
        if (!exact) return;
        const sRes = await fetch(`${backend}/api/targets/${exact.target_id}/nuclei`, { cache: "no-store" });
        if (!sRes.ok) return;
        const scans = (await sRes.json()) as { result_file: string; scan_at: string }[];
        const latest = scans?.[0];
        if (!latest?.result_file) return;
        if (cancelled) return;
        setNucleiPhase("done");
        setNucleiStatus("Done. Loaded latest result");
        setNucleiResultFile(latest.result_file);
      } catch {
        // ignore
      }
    };

    // quick retry loop, then stop (avoid infinite polling)
    const id = window.setInterval(() => void tick(), 3500);
    void tick();
    const stop = window.setTimeout(() => window.clearInterval(id), 25000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
      window.clearTimeout(stop);
    };
  }, [selectedTools.nuclei, nucleiPhase, nucleiResultFile, backend, targetUrl]);

  const toggleTool = useCallback((id: ToolId) => {
    setSelectedTools((prev) => {
      const next = { ...prev, [id]: !prev[id] };
      if (next[id]) setConfigModalTool(id);
      return next;
    });
  }, []);

  function buildKatanaFlags(): string[] {
    const flags: string[] = [];
    const depth = Number(katanaValues["-depth"]);
    if (katanaEnabled["-depth"] && Number.isFinite(depth) && depth > 0) {
      flags.push("-d", String(depth));
    }
    (katanaFlagsMeta?.flags || []).forEach((f) => {
      if (f.name === "-u" || f.name === "-depth") return;
      if (!katanaEnabled[f.name]) return;
      if (f.type === "boolean") {
        flags.push(f.name);
        return;
      }
      if (f.multiple) {
        const raw = String(katanaValues[f.name] || "");
        raw.split("\n").map((s) => s.trim()).filter(Boolean).forEach((line) => {
          flags.push(f.name, line);
        });
        return;
      }
      if (f.type === "number") {
        const v = Number(katanaValues[f.name]);
        if (Number.isFinite(v)) flags.push(f.name, String(v));
        return;
      }
      const v = String(katanaValues[f.name] ?? "").trim();
      if (v) flags.push(f.name, v);
    });
    return flags;
  }

  function buildFfufFlags(): string[] {
    const flags: string[] = [];
    if (ffufMc.trim()) flags.push("-mc", ffufMc.trim());
    if (ffufFc.trim()) flags.push("-fc", ffufFc.trim());
    if (ffufThreads !== "" && Number(ffufThreads) > 0) flags.push("-t", String(ffufThreads));
    if (ffufRate !== "" && Number(ffufRate) > 0) flags.push("-rate", String(ffufRate));
    if (ffufExtensions.trim()) flags.push("-e", ffufExtensions.trim());
    if (ffufFollowRedirects) flags.push("-r");
    if (ffufAutoCalibrate) flags.push("-ac");
    return flags;
  }

  function getKatanaConfigSummary(): string {
    const parts: string[] = [];
    const depth = Number(katanaValues["-depth"]);
    if (katanaEnabled["-depth"] && Number.isFinite(depth) && depth > 0) {
      parts.push(`-depth ${depth}`);
    }
    (katanaFlagsMeta?.flags || []).forEach((f) => {
      if (f.name === "-u" || f.name === "-depth") return;
      if (!katanaEnabled[f.name]) return;
      if (f.type === "boolean") {
        parts.push(f.name);
        return;
      }
      if (f.type === "number") {
        const v = Number(katanaValues[f.name]);
        if (Number.isFinite(v)) parts.push(`${f.name} ${v}`);
        return;
      }
      const v = String(katanaValues[f.name] ?? "").trim();
      if (v) parts.push(`${f.name} ${v}`);
    });
    return parts.length ? parts.join(", ") : "default";
  }

  function getFfufConfigSummary(): string {
    const parts: string[] = [];
    parts.push(ffufWordlistMode === "upload" ? (ffufUploadedFileId ? "wordlist: อัปโหลด" : "wordlist: ยังไม่อัปโหลด") : "wordlist: SecLists");
    if (ffufMc.trim()) parts.push(`-mc ${ffufMc.trim()}`);
    if (ffufFc.trim()) parts.push(`-fc ${ffufFc.trim()}`);
    if (ffufThreads !== "" && Number(ffufThreads) > 0) parts.push(`-t ${ffufThreads}`);
    if (ffufRate !== "" && Number(ffufRate) > 0) parts.push(`-rate ${ffufRate}`);
    if (ffufExtensions.trim()) parts.push(`-e ${ffufExtensions.trim()}`);
    if (ffufFollowRedirects) parts.push("-r");
    if (ffufAutoCalibrate) parts.push("-ac");
    return parts.join(", ");
  }

  async function handleFfufFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !file.name.toLowerCase().endsWith(".txt")) return;
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`${backend}/api/upload/wordlist`, { method: "POST", body: form });
    const data = (await res.json()) as { fileId?: string };
    if (data.fileId) {
      setFfufUploadedFileId(data.fileId);
      setFfufWordlistMode("upload");
    }
    e.target.value = "";
  }

  function handleRunClick() {
    const runAnyUrlTool =
      selectedTools.katana ||
      selectedTools.ffuf ||
      selectedTools.payload_recon ||
      selectedTools.nuclei ||
      selectedTools.whatweb ||
      selectedTools.subfinder;
    if (runAnyUrlTool) {
      const urlErr = validateUrl(targetUrl);
      if (urlErr) {
        setErrorModalMessage(urlErr);
        return;
      }
    }
    const runKatana = selectedTools.katana;
    const runFfuf = selectedTools.ffuf;
    const runNuclei = selectedTools.nuclei;
    const runWhatweb = selectedTools.whatweb;
    const runSubfinder = selectedTools.subfinder;
    const runLan = selectedTools.lan;
    if (!runKatana && !runFfuf && !runNuclei && !runWhatweb && !runSubfinder && !runLan) {
      setErrorModalMessage("กรุณาเลือกอย่างน้อย 1 tool");
      return;
    }
    if (runLan && !lanCidr.trim()) {
      setErrorModalMessage("กรุณาใส่ CIDR สำหรับ LAN scan");
      return;
    }
    startRun();
  }

  function startRun() {
    // Skip tools that are already Done (e.g. loaded from previous scans)
    const runKatana = selectedTools.katana && katanaPhase !== "done";
    const runFfuf = selectedTools.ffuf && ffufPhase !== "done";
    const runNuclei = selectedTools.nuclei && nucleiPhase !== "done";
    const runWhatweb = selectedTools.whatweb && whatwebPhase !== "done";
    const runSubfinder = selectedTools.subfinder && subfinderPhase !== "done";
    const runLan = selectedTools.lan && lanPhase !== "done";
    if (runFfuf && ffufWordlistMode === "upload" && !ffufUploadedFileId) {
      setErrorModalMessage("กรุณาอัปโหลด wordlist (.txt) สำหรับ FFuf ก่อน");
      return;
    }

    if (runKatana) {
      setKatanaPhase("idle");
      setKatanaStatus("");
      setKatanaJobId(null);
      setKatanaResultFile(null);
      setKatanaLogs([]);
    }
    if (runFfuf) {
      setFfufPhase("idle");
      setFfufStatus("");
      setFfufJobId(null);
      setFfufResultFile(null);
      setFfufLogs([]);
    }
    if (runSubfinder) {
      setSubfinderPhase("idle");
      setSubfinderStatus("");
      setSubfinderJobId(null);
      setSubfinderResultFile(null);
      setSubfinderLogs([]);
    }
    if (runLan) {
      setLanPhase("idle");
      setLanStatus("");
      setLanJobId(null);
      setLanResultFile(null);
      setLanLogs([]);
    }
    setPayloadPhase("idle");
    setPayloadEntries(null);
    payloadReconStartedRef.current = false;

    if (runKatana) {
      setKatanaPhase("starting");
      setKatanaStatus("Connecting...");
      katanaWsRef.current?.close();
      const ws = new WebSocket(wsUrl);
      katanaWsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          if (msg.type === "status") {
            setKatanaPhase(msg.status === "starting" || msg.status === "processing" || msg.status === "scoring" ? msg.status : "starting");
            if (msg.message) setKatanaStatus(msg.message);
          } else if (msg.type === "progress" && msg.message?.trim()) {
            setKatanaLogs((prev) => [...prev, msg.message.trimEnd()]);
          } else if (msg.type === "done") {
            setKatanaPhase("done");
            setKatanaStatus(`Done. ${msg.scoredUrls ?? "?"} URLs scored`);
            if (msg.resultFile) setKatanaResultFile(msg.resultFile);
          } else if (msg.type === "error") {
            setKatanaPhase("error");
            setKatanaStatus(msg.message);
          }
        } catch {}
      };
      ws.onopen = async () => {
        try {
          const res = await fetch(`${backend}/api/scan/katana`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: targetUrl.trim(), flags: buildKatanaFlags() }),
          });
          const data = (await res.json()) as { jobId?: string; error?: string };
          if (!data.jobId) {
            setKatanaPhase("error");
            setKatanaStatus(data.error || "Failed to start");
            return;
          }
          setKatanaJobId(data.jobId);
          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
          setKatanaStatus("Subscribed. Running...");
        } catch (e) {
          setKatanaPhase("error");
          setKatanaStatus((e as Error).message);
        }
      };
      ws.onerror = () => {
        setKatanaPhase("error");
        setKatanaStatus("WebSocket error");
      };
    }

    if (runFfuf) {
      setFfufPhase("starting");
      setFfufStatus("Connecting...");
      ffufWsRef.current?.close();
      const ws = new WebSocket(wsUrl);
      ffufWsRef.current = ws;
      const wordlist = ffufWordlistMode === "default" ? "default" : (ffufUploadedFileId ? { fileId: ffufUploadedFileId } : "default");
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          if (msg.type === "status") {
            setFfufPhase(msg.status === "starting" || msg.status === "processing" || msg.status === "scoring" ? msg.status : "starting");
            if (msg.message) setFfufStatus(msg.message);
          } else if (msg.type === "progress" && msg.message?.trim()) {
            setFfufLogs((prev) => [...prev, msg.message.trimEnd()]);
          } else if (msg.type === "done") {
            setFfufPhase("done");
            setFfufStatus(`Done. ${msg.scoredUrls ?? "?"} URLs scored`);
            if (msg.resultFile) setFfufResultFile(msg.resultFile);
          } else if (msg.type === "error") {
            setFfufPhase("error");
            setFfufStatus(msg.message);
          }
        } catch {}
      };
      ws.onopen = async () => {
        try {
          const res = await fetch(`${backend}/api/scan/ffuf`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: targetUrl.trim(), wordlist, flags: buildFfufFlags() }),
          });
          const data = (await res.json()) as { jobId?: string; error?: string };
          if (!data.jobId) {
            setFfufPhase("error");
            setFfufStatus(data.error || "Failed to start");
            return;
          }
          setFfufJobId(data.jobId);
          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
          setFfufStatus("Subscribed. Running...");
        } catch (e) {
          setFfufPhase("error");
          setFfufStatus((e as Error).message);
        }
      };
      ws.onerror = () => {
        setFfufPhase("error");
        setFfufStatus("WebSocket error");
      };
    }

    if (runNuclei) {
      setNucleiPhase("starting");
      setNucleiStatus("Connecting...");
      nucleiWsRef.current?.close();
      const ws = new WebSocket(wsUrl);
      nucleiWsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          if (msg.type === "status") {
            setNucleiPhase(msg.status === "starting" || msg.status === "processing" || msg.status === "scoring" ? msg.status : "starting");
            if (msg.message) setNucleiStatus(msg.message);
          } else if (msg.type === "progress" && msg.message?.trim()) {
            setNucleiLogs((prev) => [...prev, msg.message.trimEnd()]);
          } else if (msg.type === "done") {
            setNucleiPhase("done");
            setNucleiStatus(`Done. ${msg.totalFindings ?? "?"} findings`);
            if (msg.resultFile) setNucleiResultFile(msg.resultFile);
          } else if (msg.type === "error") {
            setNucleiPhase("error");
            setNucleiStatus(msg.message);
          }
        } catch {}
      };
      ws.onopen = async () => {
        try {
          const res = await fetch(`${backend}/api/scan/nuclei`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: targetUrl.trim() }),
          });
          const data = (await res.json()) as { jobId?: string; error?: string };
          if (!data.jobId) {
            setNucleiPhase("error");
            setNucleiStatus(data.error || "Failed to start");
            return;
          }
          setNucleiJobId(data.jobId);
          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
          setNucleiStatus("Subscribed. Running...");
        } catch (e) {
          setNucleiPhase("error");
          setNucleiStatus((e as Error).message);
        }
      };
      ws.onerror = () => {
        setNucleiPhase("error");
        setNucleiStatus("WebSocket error");
      };
    }

    if (runWhatweb) {
      setWhatwebPhase("starting");
      setWhatwebStatus("Connecting...");
      whatwebWsRef.current?.close();
      const ws = new WebSocket(wsUrl);
      whatwebWsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          if (msg.type === "status") {
            setWhatwebPhase(msg.status === "starting" || msg.status === "processing" || msg.status === "scoring" ? msg.status : "starting");
            if (msg.message) setWhatwebStatus(msg.message);
          } else if (msg.type === "progress" && msg.message?.trim()) {
            setWhatwebLogs((prev) => [...prev, msg.message.trimEnd()]);
          } else if (msg.type === "done") {
            setWhatwebPhase("done");
            setWhatwebStatus("Done.");
            if (msg.resultFile) setWhatwebResultFile(msg.resultFile);
          } else if (msg.type === "error") {
            setWhatwebPhase("error");
            setWhatwebStatus(msg.message);
          }
        } catch {}
      };
      ws.onopen = async () => {
        try {
          const res = await fetch(`${backend}/api/scan/whatweb`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: targetUrl.trim(), aggression: whatwebAggression }),
          });
          const data = (await res.json()) as { jobId?: string; error?: string };
          if (!data.jobId) {
            setWhatwebPhase("error");
            setWhatwebStatus(data.error || "Failed to start");
            return;
          }
          setWhatwebJobId(data.jobId);
          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
          setWhatwebStatus("Subscribed. Running...");
        } catch (e) {
          setWhatwebPhase("error");
          setWhatwebStatus((e as Error).message);
        }
      };
      ws.onerror = () => {
        setWhatwebPhase("error");
        setWhatwebStatus("WebSocket error");
      };
    }

    if (runSubfinder) {
      setSubfinderPhase("starting");
      setSubfinderStatus("Connecting...");
      subfinderWsRef.current?.close();
      const ws = new WebSocket(wsUrl);
      subfinderWsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          if (msg.type === "status") {
            setSubfinderPhase(msg.status === "starting" || msg.status === "processing" || msg.status === "scoring" ? msg.status : "starting");
            if (msg.message) setSubfinderStatus(msg.message);
          } else if (msg.type === "progress" && msg.message?.trim()) {
            setSubfinderLogs((prev) => [...prev, msg.message.trimEnd()]);
          } else if (msg.type === "done") {
            setSubfinderPhase("done");
            setSubfinderStatus("Done.");
            if (msg.resultFile) setSubfinderResultFile(msg.resultFile);
          } else if (msg.type === "error") {
            setSubfinderPhase("error");
            setSubfinderStatus(msg.message);
          }
        } catch {}
      };
      ws.onopen = async () => {
        try {
          const res = await fetch(`${backend}/api/scan/subfinder`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              target_url: targetUrl.trim(),
              httpx_timeout_sec: subfinderHttpxTimeoutSec === "" ? undefined : subfinderHttpxTimeoutSec,
            }),
          });
          const data = (await res.json()) as { jobId?: string; error?: string };
          if (!data.jobId) {
            setSubfinderPhase("error");
            setSubfinderStatus(data.error || "Failed to start");
            return;
          }
          setSubfinderJobId(data.jobId);
          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
          setSubfinderStatus("Subscribed. Running...");
        } catch (e) {
          setSubfinderPhase("error");
          setSubfinderStatus((e as Error).message);
        }
      };
      ws.onerror = () => {
        setSubfinderPhase("error");
        setSubfinderStatus("WebSocket error");
      };
    }

    if (runLan) {
      setLanPhase("starting");
      setLanStatus("Connecting...");
      lanWsRef.current?.close();
      const ws = new WebSocket(wsUrl);
      lanWsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          if (msg.type === "status") {
            setLanPhase(
              msg.status === "starting" || msg.status === "processing" || msg.status === "scoring"
                ? msg.status
                : "starting",
            );
            if (msg.message) setLanStatus(msg.message);
          } else if (msg.type === "progress" && msg.message?.trim()) {
            setLanLogs((prev) => [...prev, msg.message.trimEnd()]);
          } else if (msg.type === "done") {
            setLanPhase("done");
            setLanStatus("Done.");
            if (msg.resultFile) setLanResultFile(msg.resultFile);
          } else if (msg.type === "error") {
            setLanPhase("error");
            setLanStatus(msg.message);
          }
        } catch {
          // ignore
        }
      };
      ws.onopen = async () => {
        try {
          let ports: string;
          if (lanPortsPreset === "custom") {
            ports = lanCustomPorts.trim() || "top100";
          } else {
            ports = lanPortsPreset;
          }
          const res = await fetch(`${backend}/api/scan/lan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              cidr: lanCidr.trim(),
              mode: lanMode,
              ports,
            }),
          });
          const data = (await res.json()) as { jobId?: string; error?: string };
          if (!data.jobId) {
            setLanPhase("error");
            setLanStatus(data.error || "Failed to start");
            return;
          }
          setLanJobId(data.jobId);
          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
          setLanStatus("Subscribed. Running...");
        } catch (e) {
          setLanPhase("error");
          setLanStatus((e as Error).message);
        }
      };
      ws.onerror = () => {
        setLanPhase("error");
        setLanStatus("WebSocket error");
      };
    }

  }

  function resetKatanaForRescan() {
    setKatanaPhase("idle");
    setKatanaStatus("");
    setKatanaJobId(null);
    setKatanaResultFile(null);
    setKatanaLogs([]);
    payloadReconStartedRef.current = false;
    setPayloadPhase("idle");
    setPayloadEntries(null);
    setPayloadResultFile(null);
    setPayloadReconId(null);
  }

  function resetFfufForRescan() {
    setFfufPhase("idle");
    setFfufStatus("");
    setFfufJobId(null);
    setFfufResultFile(null);
    setFfufLogs([]);
    payloadReconStartedRef.current = false;
    setPayloadPhase("idle");
    setPayloadEntries(null);
    setPayloadResultFile(null);
    setPayloadReconId(null);
  }

  function resetAllRound() {
    resetKatanaForRescan();
    resetFfufForRescan();
    setSelectedTools({ katana: false, ffuf: false, payload_recon: false, nuclei: false, whatweb: false, subfinder: false, lan: false });
    setNucleiPhase("idle");
    setNucleiStatus("");
    setNucleiJobId(null);
    setNucleiResultFile(null);
    setNucleiLogs([]);
    setWhatwebPhase("idle");
    setWhatwebStatus("");
    setWhatwebJobId(null);
    setWhatwebResultFile(null);
    setWhatwebLogs([]);
    setSubfinderPhase("idle");
    setSubfinderStatus("");
    setSubfinderJobId(null);
    setSubfinderResultFile(null);
    setSubfinderLogs([]);
    setLanPhase("idle");
    setLanStatus("");
    setLanJobId(null);
    setLanResultFile(null);
    setLanLogs([]);
    setOutputModalTool(null);
    setConfigModalTool(null);
  }

  async function runPayloadReconAfterScan(katanaFile: string | null, ffufFile: string | null) {
    setPayloadPhase("running");
    const urls: string[] = [];
    const seen = new Set<string>();

    if (katanaFile) {
      try {
        const res = await fetch(`${backend}/api/result?path=${encodeURIComponent(katanaFile)}`, { cache: "no-store" });
        if (res.ok) {
          const data = (await res.json()) as { url: string; status?: number }[];
          data.forEach((r) => {
            if (r.status === 403 || r.status === 302) return;
            if (r.url && !seen.has(r.url)) {
              seen.add(r.url);
              urls.push(r.url);
            }
          });
        }
      } catch {}
    }
    if (ffufFile) {
      try {
        const res = await fetch(`${backend}/api/result?path=${encodeURIComponent(ffufFile)}`, { cache: "no-store" });
        if (res.ok) {
          const data = (await res.json()) as { url: string; status?: number }[];
          data.forEach((r) => {
            if (r.status === 403 || r.status === 302) return;
            if (r.url && !seen.has(r.url)) {
              seen.add(r.url);
              urls.push(r.url);
            }
          });
        }
      } catch {}
    }

    const pathOnly = (u: string) => u.split("?")[0].toLowerCase();
    const filtered = urls.filter((u) => {
      const p = pathOnly(u);
      return !p.endsWith(".js") && !p.endsWith(".css");
    });

    if (filtered.length === 0) {
      setPayloadPhase("done");
      setPayloadEntries([]);
      return;
    }

    try {
      const res = await fetch(`${backend}/api/payload/recon`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls: filtered, target_url: targetUrl.trim() }),
      });
      const headerId = res.headers.get("x-payload-recon-id");
      const headerFile = res.headers.get("x-payload-recon-result-file");
      if (headerId) {
        const n = Number(headerId);
        if (Number.isFinite(n)) setPayloadReconId(n);
      }
      if (headerFile) setPayloadResultFile(headerFile);
      const data = (await res.json()) as PayloadEntry[] | { error?: string };
      if (Array.isArray(data)) {
        setPayloadPhase("done");
        setPayloadEntries(data);
      } else {
        setPayloadPhase("error");
        setErrorModalMessage((data as { error?: string }).error || "Payload recon failed");
      }
    } catch (e) {
      setPayloadPhase("error");
      setErrorModalMessage((e as Error).message);
    }
  }

  useEffect(() => {
    if (!selectedTools.payload_recon || payloadPhase !== "idle" || payloadReconStartedRef.current) return;
    const katanaDone = !selectedTools.katana || katanaPhase === "done" || katanaPhase === "error";
    const ffufDone = !selectedTools.ffuf || ffufPhase === "done" || ffufPhase === "error";
    if (!katanaDone || !ffufDone) return;
    const katanaFile = selectedTools.katana ? katanaResultFile : null;
    const ffufFile = selectedTools.ffuf ? ffufResultFile : null;
    if (!katanaFile && !ffufFile) {
      setPayloadPhase("done");
      setPayloadEntries([]);
      return;
    }
    payloadReconStartedRef.current = true;
    runPayloadReconAfterScan(katanaFile, ffufFile);
  }, [selectedTools.katana, selectedTools.ffuf, selectedTools.payload_recon, katanaPhase, ffufPhase, katanaResultFile, ffufResultFile, payloadPhase]);

  return (
    <>
      <ErrorModal
        open={!!errorModalMessage}
        message={errorModalMessage ?? ""}
        onClose={() => setErrorModalMessage(null)}
      />
      <div className="flex min-h-0 flex-1">
        {/* Sidebar */}
        <aside className="flex w-64 shrink-0 flex-col border-r border-zinc-200 bg-white p-4">
          <h2 className="text-sm font-semibold text-zinc-800">Tools</h2>
          <p className="mt-1 text-xs text-zinc-500">เลือก tools ที่จะรันในรอบนี้</p>
          <div className="mt-4 space-y-2">
            {(
              [
                { id: "katana" as const, label: "Katana Scan", desc: "Crawl + Gemini score" },
                { id: "ffuf" as const, label: "FFuf Hidden Path", desc: "Wordlist + Gemini score" },
                { id: "payload_recon" as const, label: "Payload Recon", desc: "รันหลัง Katana/FFuf" },
                { id: "nuclei" as const, label: "Nuclei", desc: "Templates scan (filtered JSON output)" },
                { id: "whatweb" as const, label: "WhatWeb", desc: "Fingerprint (dynamic plugins JSON)" },
                { id: "subfinder" as const, label: "Subfinder", desc: "Subdomains + httpx (alive 200)" },
                { id: "lan" as const, label: "LAN Scanner", desc: "สแกน LAN จาก CIDR" },
              ] as const
            ).map(({ id, label, desc }) => (
              <label
                key={id}
                className={cn(
                  "flex items-start gap-2 rounded-lg border border-zinc-200 p-3",
                  anyRunning ? "cursor-not-allowed opacity-60" : "cursor-pointer hover:bg-zinc-50"
                )}
              >
                <input
                  type="checkbox"
                  checked={selectedTools[id]}
                  disabled={anyRunning}
                  onChange={() => !anyRunning && toggleTool(id)}
                  className="mt-0.5"
                />
                <div>
                  <span className="text-sm font-medium text-zinc-900">{label}</span>
                  <p className="text-[11px] text-zinc-500">{desc}</p>
                </div>
              </label>
            ))}
          </div>
          <div className="mt-6">
            <button
              type="button"
              onClick={handleRunClick}
              disabled={anyRunning}
              className={cn(
                "w-full rounded-xl py-2.5 text-sm font-semibold shadow-md transition",
                anyRunning ? "cursor-not-allowed bg-zinc-200 text-zinc-500" : "bg-gradient-to-r from-amber-500 to-amber-600 text-white hover:from-amber-600 hover:to-amber-700",
              )}
            >
              {anyRunning ? "กำลังรัน..." : "Run"}
            </button>
          </div>
        </aside>

        {/* Main */}
        <main className="min-w-0 flex-1 overflow-auto p-6">
          <div className="mb-8">
            <label className="block text-xs font-semibold text-zinc-500 uppercase tracking-wider">Target URL</label>
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com/"
              className="mt-2 w-full max-w-xl rounded-2xl border border-zinc-200 bg-white px-4 py-3 text-sm shadow-sm outline-none ring-2 ring-transparent focus:border-amber-400 focus:ring-amber-400/30"
            />
            <div className="mt-3 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => setLoadPreviousOpen(true)}
                disabled={anyRunning}
                className={cn(
                  "rounded-xl border px-4 py-2 text-sm font-semibold transition",
                  anyRunning
                    ? "cursor-not-allowed border-zinc-200 bg-zinc-100 text-zinc-400"
                    : "border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50"
                )}
              >
                โหลดข้อมูลเดิม
              </button>
              <button
                type="button"
                onClick={resetAllRound}
                disabled={anyRunning}
                className={cn(
                  "rounded-xl border px-4 py-2 text-sm font-semibold transition",
                  anyRunning
                    ? "cursor-not-allowed border-zinc-200 bg-zinc-100 text-zinc-400"
                    : "border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50"
                )}
              >
                ล้างข้อมูลรอบนี้
              </button>
            </div>
          </div>

          {/* Tool output cards — click Done/Error to open output modal */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {selectedTools.katana && (
              <ToolCard
                label="Katana"
                phase={katanaPhase}
                status={katanaStatus}
                configSummary={getKatanaConfigSummary()}
                onClick={() => {
                  const running = katanaPhase === "starting" || katanaPhase === "processing" || katanaPhase === "scoring";
                  if (katanaPhase === "idle") setConfigModalTool("katana");
                  else setOutputModalTool("katana");
                }}
                canClickOutput={katanaPhase === "done" || katanaPhase === "error"}
                isRunning={katanaPhase === "starting" || katanaPhase === "processing" || katanaPhase === "scoring"}
                clickable={true}
                onRescan={katanaPhase === "done" || katanaPhase === "error" ? resetKatanaForRescan : undefined}
              />
            )}
            {selectedTools.ffuf && (
              <ToolCard
                label="FFuf"
                phase={ffufPhase}
                status={ffufStatus}
                configSummary={getFfufConfigSummary()}
                onClick={() => {
                  if (ffufPhase === "idle") setConfigModalTool("ffuf");
                  else setOutputModalTool("ffuf");
                }}
                canClickOutput={ffufPhase === "done" || ffufPhase === "error"}
                isRunning={ffufPhase === "starting" || ffufPhase === "processing" || ffufPhase === "scoring"}
                clickable={true}
                onRescan={ffufPhase === "done" || ffufPhase === "error" ? resetFfufForRescan : undefined}
              />
            )}
            {selectedTools.payload_recon && (
              <ToolCard
                label="Payload Recon"
                phase={payloadPhase === "error" ? "error" : payloadPhase === "done" ? "done" : payloadPhase === "running" ? "running" : "idle"}
                status={
                  payloadPhase === "idle"
                    ? "รอ Katana/FFuf"
                    : payloadPhase === "running"
                      ? "กำลังรัน..."
                      : payloadPhase === "done"
                        ? `พบ ${payloadEntries?.length ?? 0} รายการ`
                        : "เกิดข้อผิดพลาด"
                }
                configSummary="รันหลัง Katana/FFuf เสร็จ"
                onClick={() => (payloadPhase === "done" || payloadPhase === "error") ? setOutputModalTool("payload_recon") : setConfigModalTool("payload_recon")}
                canClickOutput={payloadPhase === "done" || payloadPhase === "error"}
                isRunning={payloadPhase === "running"}
                clickable={payloadPhase === "done" || payloadPhase === "error" || payloadPhase === "idle"}
                onRescan={
                  payloadPhase === "done" || payloadPhase === "error"
                    ? () => {
                        payloadReconStartedRef.current = false;
                        setPayloadPhase("idle");
                        setPayloadEntries(null);
                      }
                    : undefined
                }
              />
            )}
            {selectedTools.nuclei && (
              <ToolCard
                label="Nuclei"
                phase={nucleiPhase}
                status={nucleiStatus}
                configSummary="jsonl → filtered JSON"
                onClick={() => {
                  if (nucleiPhase === "idle") setConfigModalTool("nuclei");
                  else setOutputModalTool("nuclei");
                }}
                canClickOutput={nucleiPhase === "done" || nucleiPhase === "error"}
                isRunning={nucleiPhase === "starting" || nucleiPhase === "processing" || nucleiPhase === "scoring"}
                clickable={true}
                onRescan={nucleiPhase === "done" || nucleiPhase === "error" ? () => {
                  setNucleiPhase("idle");
                  setNucleiStatus("");
                  setNucleiJobId(null);
                  setNucleiResultFile(null);
                  setNucleiLogs([]);
                } : undefined}
              />
            )}
            {selectedTools.whatweb && (
              <ToolCard
                label="WhatWeb"
                phase={whatwebPhase}
                status={whatwebStatus}
                configSummary={`-a ${whatwebAggression}`}
                onClick={() => {
                  if (whatwebPhase === "idle") setConfigModalTool("whatweb");
                  else setOutputModalTool("whatweb");
                }}
                canClickOutput={whatwebPhase === "done" || whatwebPhase === "error"}
                isRunning={whatwebPhase === "starting" || whatwebPhase === "processing" || whatwebPhase === "scoring"}
                clickable={true}
                onRescan={whatwebPhase === "done" || whatwebPhase === "error" ? () => {
                  setWhatwebPhase("idle");
                  setWhatwebStatus("");
                  setWhatwebJobId(null);
                  setWhatwebResultFile(null);
                  setWhatwebLogs([]);
                } : undefined}
              />
            )}

            {selectedTools.subfinder && (
              <ToolCard
                label="Subfinder"
                phase={subfinderPhase}
                status={subfinderStatus}
                configSummary={`httpx timeout: ${subfinderHttpxTimeoutSec || 5}s`}
                onClick={() => {
                  if (subfinderPhase === "idle") setConfigModalTool("subfinder");
                  else setOutputModalTool("subfinder");
                }}
                canClickOutput={subfinderPhase === "done" || subfinderPhase === "error"}
                isRunning={subfinderPhase === "starting" || subfinderPhase === "processing" || subfinderPhase === "scoring"}
                clickable={true}
                onRescan={subfinderPhase === "done" || subfinderPhase === "error" ? () => {
                  setSubfinderPhase("idle");
                  setSubfinderStatus("");
                  setSubfinderJobId(null);
                  setSubfinderResultFile(null);
                  setSubfinderLogs([]);
                } : undefined}
              />
            )}

            {selectedTools.lan && (
              <ToolCard
                label="LAN Scanner"
                phase={lanPhase}
                status={lanStatus}
                configSummary={`${lanCidr} • ${lanMode} • ${
                  lanPortsPreset === "custom" ? (lanCustomPorts || "ports: custom") : lanPortsPreset
                }`}
                onClick={() => {
                  if (lanPhase === "idle") setConfigModalTool("lan");
                  else setOutputModalTool("lan");
                }}
                canClickOutput={lanPhase === "done" || lanPhase === "error"}
                isRunning={lanPhase === "starting" || lanPhase === "processing" || lanPhase === "scoring"}
                clickable={true}
                onRescan={
                  lanPhase === "done" || lanPhase === "error"
                    ? () => {
                        setLanPhase("idle");
                        setLanStatus("");
                        setLanJobId(null);
                        setLanResultFile(null);
                        setLanLogs([]);
                      }
                    : undefined
                }
              />
            )}
          </div>

          {!selectedTools.katana && !selectedTools.ffuf && !selectedTools.payload_recon && !selectedTools.nuclei && !selectedTools.whatweb && !selectedTools.subfinder && !selectedTools.lan && (
            <div className="rounded-2xl border-2 border-dashed border-zinc-200 bg-zinc-50/50 p-12 text-center">
              <p className="text-sm font-medium text-zinc-500">เลือก tools ด้านซ้าย จะเปิด modal ตั้งค่าของ tool นั้น แล้วกด Run เพื่อเริ่มสแกน</p>
            </div>
          )}
        </main>
      </div>

      <ConfigModal
        open={configModalTool !== null}
        tool={configModalTool}
        onClose={() => setConfigModalTool(null)}
        katanaFlagsMeta={katanaFlagsMeta}
        katanaEnabled={katanaEnabled}
        katanaValues={katanaValues}
        setKatanaEnabled={setKatanaEnabled}
        setKatanaValues={setKatanaValues}
        ffufWordlistMode={ffufWordlistMode}
        setFfufWordlistMode={setFfufWordlistMode}
        ffufUploadedFileId={ffufUploadedFileId}
        ffufFileInputRef={ffufFileInputRef}
        onFfufFileSelect={handleFfufFileSelect}
        ffufMc={ffufMc}
        setFfufMc={setFfufMc}
        ffufFc={ffufFc}
        setFfufFc={setFfufFc}
        ffufThreads={ffufThreads}
        setFfufThreads={setFfufThreads}
        ffufRate={ffufRate}
        setFfufRate={setFfufRate}
        ffufExtensions={ffufExtensions}
        setFfufExtensions={setFfufExtensions}
        ffufFollowRedirects={ffufFollowRedirects}
        setFfufFollowRedirects={setFfufFollowRedirects}
        ffufAutoCalibrate={ffufAutoCalibrate}
        setFfufAutoCalibrate={setFfufAutoCalibrate}
        whatwebAggression={whatwebAggression}
        setWhatwebAggression={setWhatwebAggression}
        subfinderHttpxTimeoutSec={subfinderHttpxTimeoutSec}
        setSubfinderHttpxTimeoutSec={setSubfinderHttpxTimeoutSec}
        lanCidr={lanCidr}
        setLanCidr={setLanCidr}
        lanMode={lanMode}
        setLanMode={setLanMode}
        lanPortsPreset={lanPortsPreset}
        setLanPortsPreset={setLanPortsPreset}
        lanCustomPorts={lanCustomPorts}
        setLanCustomPorts={setLanCustomPorts}
      />

      <OutputModal
        open={outputModalTool !== null}
        onClose={() => setOutputModalTool(null)}
        toolId={outputModalTool ?? "katana"}
        title={outputModalTool ?? "Katana"}
        phase={
          outputModalTool === "katana"
            ? (katanaPhase === "starting" || katanaPhase === "processing" || katanaPhase === "scoring" ? "running" : katanaPhase === "error" ? "error" : "done")
            : outputModalTool === "ffuf"
              ? (ffufPhase === "starting" || ffufPhase === "processing" || ffufPhase === "scoring" ? "running" : ffufPhase === "error" ? "error" : "done")
              : outputModalTool === "nuclei"
                ? (nucleiPhase === "starting" || nucleiPhase === "processing" || nucleiPhase === "scoring" ? "running" : nucleiPhase === "error" ? "error" : "done")
                : outputModalTool === "whatweb"
                  ? (whatwebPhase === "starting" || whatwebPhase === "processing" || whatwebPhase === "scoring" ? "running" : whatwebPhase === "error" ? "error" : "done")
                  : outputModalTool === "subfinder"
                    ? (subfinderPhase === "starting" || subfinderPhase === "processing" || subfinderPhase === "scoring" ? "running" : subfinderPhase === "error" ? "error" : "done")
              : payloadPhase === "error"
                ? "error"
                : "done"
        }
        status={
          outputModalTool === "katana"
            ? katanaStatus
            : outputModalTool === "ffuf"
              ? ffufStatus
              : outputModalTool === "nuclei"
                ? nucleiStatus
                : outputModalTool === "whatweb"
                  ? whatwebStatus
                  : outputModalTool === "subfinder"
                    ? subfinderStatus
                    : outputModalTool === "lan"
                      ? lanStatus
                      : payloadPhase === "done"
                        ? `พบ ${payloadEntries?.length ?? 0} รายการ`
                        : "เกิดข้อผิดพลาด"
        }
        logs={
          outputModalTool === "katana"
            ? katanaLogs
            : outputModalTool === "ffuf"
              ? ffufLogs
              : outputModalTool === "nuclei"
                ? nucleiLogs
                : outputModalTool === "whatweb"
                  ? whatwebLogs
                  : outputModalTool === "subfinder"
                    ? subfinderLogs
                    : outputModalTool === "lan"
                      ? lanLogs
                      : undefined
        }
        resultFile={
          outputModalTool === "katana"
            ? katanaResultFile
            : outputModalTool === "ffuf"
              ? ffufResultFile
              : outputModalTool === "nuclei"
                ? nucleiResultFile
                : outputModalTool === "whatweb"
                  ? whatwebResultFile
                  : outputModalTool === "subfinder"
                    ? subfinderResultFile
                    : outputModalTool === "lan"
                      ? lanResultFile
                      : null
        }
        backend={backend}
        payloadEntries={outputModalTool === "payload_recon" ? payloadEntries : undefined}
        payloadReconId={outputModalTool === "payload_recon" ? payloadReconId : null}
      />

      <LoadPreviousModal
        open={loadPreviousOpen}
        onClose={() => setLoadPreviousOpen(false)}
        backend={backend}
        targetUrl={targetUrl}
        onApply={(sel) => {
          // Apply selected previous scans as Done states
          setSelectedTools((prev) => ({
            ...prev,
            katana: prev.katana || !!sel.katana,
            ffuf: prev.ffuf || !!sel.ffuf,
            payload_recon: prev.payload_recon, // user can enable separately
            nuclei: prev.nuclei || !!sel.nuclei,
            whatweb: prev.whatweb || !!sel.whatweb,
            subfinder: prev.subfinder || !!sel.subfinder,
          }));
          if (sel.katana) {
            setKatanaPhase("done");
            setKatanaStatus("Loaded previous scan");
            setKatanaJobId(null);
            setKatanaResultFile(sel.katana.result_file);
            setKatanaLogs([]);
          }
          if (sel.ffuf) {
            setFfufPhase("done");
            setFfufStatus("Loaded previous scan");
            setFfufJobId(null);
            setFfufResultFile(sel.ffuf.result_file);
            setFfufLogs([]);
          }
          if (sel.payload_recon) {
            setSelectedTools((prev) => ({ ...prev, payload_recon: true }));
            setPayloadPhase("done");
            setPayloadResultFile(sel.payload_recon.result_file);
            setPayloadReconId(sel.payload_recon.id);
            setPayloadEntries(null);
            // load payload entries from file
            fetch(`${backend}/api/result?path=${encodeURIComponent(sel.payload_recon.result_file)}`, { cache: "no-store" })
              .then((r) => r.json())
              .then((data) => {
                if (Array.isArray(data)) setPayloadEntries(data as PayloadReconEntry[]);
                else setPayloadEntries([]);
              })
              .catch(() => setPayloadEntries([]));
          }
          if (sel.nuclei) {
            setSelectedTools((prev) => ({ ...prev, nuclei: true }));
            setNucleiPhase("done");
            setNucleiStatus("Loaded previous scan");
            setNucleiJobId(null);
            setNucleiResultFile(sel.nuclei.result_file);
            setNucleiLogs([]);
          }
          if (sel.whatweb) {
            setSelectedTools((prev) => ({ ...prev, whatweb: true }));
            setWhatwebPhase("done");
            setWhatwebStatus("Loaded previous scan");
            setWhatwebJobId(null);
            setWhatwebResultFile(sel.whatweb.result_file);
            setWhatwebLogs([]);
          }
          if (sel.subfinder) {
            setSelectedTools((prev) => ({ ...prev, subfinder: true }));
            setSubfinderPhase("done");
            setSubfinderStatus("Loaded previous scan");
            setSubfinderJobId(null);
            setSubfinderResultFile(sel.subfinder.result_file);
            setSubfinderLogs([]);
          }
          payloadReconStartedRef.current = false;
          if (!sel.payload_recon) {
            setPayloadPhase("idle");
            setPayloadEntries(null);
            setPayloadResultFile(null);
            setPayloadReconId(null);
          }
        }}
      />
    </>
  );
}

function ToolCard({
  label,
  phase,
  status,
  configSummary,
  onClick,
  canClickOutput,
  isRunning,
  clickable,
  onRescan,
}: {
  label: string;
  phase: JobPhase | "running";
  status: string;
  configSummary?: string;
  onClick: () => void;
  canClickOutput: boolean;
  isRunning: boolean;
  clickable: boolean;
  onRescan?: () => void;
}) {
  const isDone = phase === "done";
  const isError = phase === "error";
  const running =
    phase === "starting" || phase === "processing" || phase === "scoring" || phase === "running";
  const isIdle = !isDone && !isError && !running;
  const showStatus = status.trim();
  const displayMain = isIdle ? (showStatus || configSummary || "—") : (showStatus || "—");

  return (
    <div
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onClick={clickable ? onClick : undefined}
      onKeyDown={clickable ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); } } : undefined}
      className={cn(
        "rounded-2xl border-2 p-5 transition",
        clickable && "cursor-pointer",
        !clickable && "cursor-default",
        isDone && "border-emerald-200 bg-emerald-50 hover:shadow-lg",
        isError && "border-red-200 bg-red-50/60 hover:shadow-lg",
        running && "border-amber-200 bg-amber-50/50",
        isIdle && "border-zinc-200 bg-white hover:border-zinc-300 hover:shadow",
        clickable && (isDone || isError) && "hover:ring-2 hover:ring-amber-400/30",
        clickable && isIdle && "hover:ring-2 hover:ring-amber-400/20",
        clickable && running && "hover:ring-2 hover:ring-amber-400/20"
      )}
    >
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-zinc-800">{label}</h4>
        {onRescan && !running && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onRescan();
            }}
            className="rounded-lg border border-zinc-200 bg-white px-2 py-1 text-[11px] font-semibold text-zinc-700 hover:bg-zinc-50"
          >
            สแกนใหม่
          </button>
        )}
        {isRunning && (
          <span className="inline-flex h-2 w-2 animate-pulse rounded-full bg-amber-500" aria-hidden />
        )}
        {isDone && <span className="text-emerald-600 text-lg">✓</span>}
        {isError && <span className="text-red-600 text-lg">⚠</span>}
      </div>
      <p className={cn(
        "mt-2 text-sm font-medium",
        isDone && "text-emerald-700",
        isError && "text-red-700",
        isRunning && "text-amber-700",
        isIdle && "text-zinc-500"
      )}>
        {displayMain}
      </p>
      {configSummary && !isIdle && !running && (
        <p className="mt-1 text-xs text-zinc-500 font-normal">ตั้งค่า: {configSummary}</p>
      )}
      <p className="mt-2 text-xs text-zinc-500">
        {!clickable ? "รอสักครู่..." : isRunning ? "คลิกเพื่อดู log" : canClickOutput ? "คลิกเพื่อดู output" : "คลิกเพื่อแก้ไขตั้งค่า"}
      </p>
    </div>
  );
}

function normalizeUrlForLookup(raw: string): string {
  const v = (raw || "").trim();
  if (!v) return "";
  try {
    const u = new URL(v);
    u.hash = "";
    const s = u.toString();
    return s.endsWith("/") ? s : s + "/";
  } catch {
    return v.endsWith("/") ? v : v + "/";
  }
}
