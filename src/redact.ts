const patterns: RegExp[] = [
  /sk-[A-Za-z0-9_-]+/g,
  /AKIA[0-9A-Z]{16}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /(postgres|mysql|mongodb|redis):\/\/[^\s'"]+/g,
  /Bearer\s+[A-Za-z0-9._-]+/g,
  /(api[_-]?key|secret|token|password)\s*[:=]\s*["']?[^"'\s]+/gi,
];

export function redact(text: string): { text: string; redactions: number } {
  let redactions = 0;
  let output = text;

  for (const pattern of patterns) {
    output = output.replace(pattern, () => {
      redactions++;
      return "<REDACTED>";
    });
  }

  return { text: output, redactions };
}