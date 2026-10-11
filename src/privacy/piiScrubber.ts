const PATTERNS = {
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  phone: /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4,6}\b/g,
  dob: /\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b/g,
  address:
    /\b\d{1,5}\s+[A-Za-z0-9\s.,#-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b/gi,
  accountNumber: /\b(?:account|acct|a\/c)[#:\s]*\d{6,16}\b/gi,
  otp: /\b(?:OTP|verification code|one[- ]time password)[:\s]*\d{4,8}\b/gi,
  standaloneOtp: /\b\d{4,8}\b(?=\s*(?:is your|verification|code|OTP))/gi,
  creditCard: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
};

const COMMON_NAME_PATTERN =
  /\b(?:Mr|Mrs|Ms|Dr)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g;

export interface ScrubResult {
  scrubbed: string;
  redactionCount: number;
  redactedTypes: string[];
}

function replaceAll(
  text: string,
  pattern: RegExp,
  replacement: string,
  type: string,
  types: Set<string>
): { text: string; count: number } {
  let count = 0;
  const result = text.replace(pattern, () => {
    count++;
    types.add(type);
    return replacement;
  });
  return { text: result, count };
}

export function scrubPII(text: string): ScrubResult {
  if (!text) {
    return { scrubbed: '', redactionCount: 0, redactedTypes: [] };
  }

  let scrubbed = text;
  let redactionCount = 0;
  const redactedTypes = new Set<string>();

  const steps: Array<[RegExp, string, string]> = [
    [PATTERNS.email, '[EMAIL]', 'email'],
    [PATTERNS.phone, '[PHONE]', 'phone'],
    [PATTERNS.creditCard, '[CARD_NUMBER]', 'credit_card'],
    [PATTERNS.dob, '[DATE_OF_BIRTH]', 'date_of_birth'],
    [PATTERNS.ssn, '[SSN]', 'ssn'],
    [PATTERNS.address, '[ADDRESS]', 'address'],
    [PATTERNS.accountNumber, '[ACCOUNT_NUMBER]', 'account_number'],
    [PATTERNS.otp, '[OTP]', 'otp'],
    [PATTERNS.standaloneOtp, '[OTP]', 'otp'],
    [COMMON_NAME_PATTERN, '[NAME]', 'name'],
  ];

  for (const [pattern, replacement, type] of steps) {
    const { text: updated, count } = replaceAll(
      scrubbed,
      pattern,
      replacement,
      type,
      redactedTypes
    );
    scrubbed = updated;
    redactionCount += count;
  }

  return {
    scrubbed,
    redactionCount,
    redactedTypes: Array.from(redactedTypes),
  };
}

export function scrubEmailData<T extends { bodyText: string; subject: string }>(
  data: T
): T & { scrubbedBody: string; scrubbedSubject: string } {
  const body = scrubPII(data.bodyText);
  const subject = scrubPII(data.subject);
  return {
    ...data,
    bodyText: body.scrubbed,
    subject: subject.scrubbed,
    scrubbedBody: body.scrubbed,
    scrubbedSubject: subject.scrubbed,
  };
}

export default scrubPII;
