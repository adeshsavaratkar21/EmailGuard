export type Classification = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
export type PageKey = 'overview' | 'email' | 'url' | 'history' | 'methodology';

export interface RiskFactor {
  code: string;
  title: string;
  description: string;
  severity: 'high' | 'medium' | 'low' | 'positive' | 'info' | string;
  contribution: number;
  direction: string;
}

export interface URLDetails {
  url: string;
  scheme: string;
  domain: string;
  registered_domain: string;
  subdomain: string;
  path: string;
  port: number;
  is_https: boolean;
  host_is_ip: boolean;
  punycode: boolean;
  domain_similarity: { detected: boolean; brand?: string | null; similarity?: number | null };
  lookalike_detected: boolean;
  lookalike_brand?: string | null;
  suspicious_keywords: string[];
  flags: Record<string, boolean>;
  redirects: {
    chain: { url: string; status?: number }[];
    redirect_count: number;
    final_url: string;
    final_domain?: string;
    domain_changed: boolean;
    https_downgrade: boolean;
    error?: string | null;
  };
  tls: {
    status: string; issuer?: string; version?: string; detail?: string;
    certificate?: {
      subject?: string; issuer?: string; valid_from?: string; valid_until?: string;
      subject_alt_names?: string[]; signature_algorithm?: string; signature_hash?: string;
      public_key?: { algorithm?: string; key_size_bits?: number | null; curve?: string };
      sha256_fingerprint?: string; hostname_match?: boolean; chain_validated?: boolean;
    };
  };
  suspicious: boolean;
  reasons: string[];
  network_checks_performed: boolean;
}

export interface EmailInfo {
  from: string;
  sender: string;
  to: string;
  reply_to: string;
  return_path: string;
  subject: string;
  date: string;
  message_id: string;
  received: string[];
  body_character_count: number;
  raw_message_size: number;
  mime_types: string[];
  attachments: { filename: string; mime_type: string; size_bytes: number; inspection: string }[];
  urls_found: number;
  urls_analyzed: number;
  urls_truncated?: boolean;
}

export interface AnalysisReport {
  analysis_id: string;
  kind: 'email' | 'url';
  filename?: string;
  created_at?: string;
  email?: EmailInfo;
  authentication?: {
    spf: { status: string; source?: string; verification_type?: string; reported_status?: string | null };
    dkim: { status: string; signing_domain?: string | null; selector?: string | null; signature_present?: boolean; source?: string; verification_type?: string; reported_status?: string | null };
    dmarc: { status: string; policy?: string | null; aligned_from_domain?: string | null; source?: string; verification_type?: string; reported_status?: string | null };
    smime?: { status: string; verification_type?: string; reported_status?: string | null };
    pgp?: { status: string; verification_type?: string; reported_status?: string | null };
    caveat?: string;
  };
  cryptography?: {
    hashes: { algorithm: string; sha256: string; sha512: string; scope: string; body_bytes: number };
    digital_signature: {
      dkim_present: boolean;
      dkim_status: string;
      smime_present: boolean;
      smime_status: string;
      pgp_present: boolean;
      pgp_status: string;
      rsa_ecc: string;
    };
    certificate?: { status: string; note?: string };
  };
  urls?: URLDetails[];
  url_analysis?: URLDetails;
  risk_score: number;
  safety_score: number;
  classification: Classification;
  recommendation: string;
  risk_label?: string;
  factors: RiskFactor[];
  reasons: string[];
  confidence?: string;
  model_note?: string;
  limitations?: string[];
}

export interface HistoryItem {
  analysis_id: string;
  kind: 'email' | 'url';
  filename?: string | null;
  sender?: string | null;
  subject?: string | null;
  url?: string | null;
  safety_score: number;
  risk_score: number;
  classification: Classification;
  recommendation: string;
  created_at?: string | null;
}

export interface DashboardStats {
  total_analyzed: number;
  safe: number;
  suspicious: number;
  malicious: number;
  average_safety_score: number;
  recent_detections: unknown[];
  recent_activity: {
    analysis_id: string;
    kind: string;
    label: string;
    classification: Classification;
    safety_score: number;
    created_at: string | null;
  }[];
  sample_data: boolean;
}
