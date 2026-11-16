/**
 * The searches the New Scan page offers (domain, IP address, email address, phone number, person name, ASN) and a
 * recogniser for what the user typed, so the page can pick the matching search and warn about a mismatch.
 *
 * The server decides which profile each search runs (GET /api/search-types); this only classifies the typed text.
 * It mirrors SpiderFootHelpers.targetTypeFromString, with one difference: a bare run of digits is a phone number when
 * it looks like one (starts with 0, or has 9 or more digits) and an ASN number otherwise.
 */

export type SearchKey = 'domain' | 'ip' | 'email' | 'phone' | 'name' | 'asn';

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(\/([0-9]|[12]\d|3[0-2]))?$/;
const IPV6 = /^[0-9a-f:]*:[0-9a-f:.]*(\/\d{1,3})?$/i;
const EMAIL = /^[^\s@"]+@[^\s@"]+\.[^\s@"]{2,}$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const ASN = /^AS\d{1,10}$/i;
const PHONE_CHARS = /^\+?[\d\s().-]+$/;

/** What a target typed into the form looks like, or null when it is empty or unrecognisable. */
export function detectSearchType(raw: string): SearchKey | null {
  let text = (raw ?? '').trim();
  if (!text) return null;
  // names are often typed or pasted with quote marks
  text = text.replace(/^["'“‘]+|["'”’]+$/g, '').trim();
  if (!text) return null;

  if (ASN.test(text)) return 'asn';
  if (IPV4.test(text)) return 'ip';
  if (text.includes(':') && !/\s/.test(text) && IPV6.test(text)) return 'ip';
  if (EMAIL.test(text)) return 'email';

  const digits = text.replace(/\D/g, '');
  if (PHONE_CHARS.test(text) && digits.length >= 7) {
    if (text.startsWith('+') || /[\s().-]/.test(text) || text.startsWith('0') || digits.length >= 9) return 'phone';
  }
  if (/^\d{1,10}$/.test(text)) return 'asn';

  const host = text.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '');
  if (DOMAIN.test(host)) return 'domain';

  // anything else with letters is a person's name or a username
  return /\p{L}/u.test(text) ? 'name' : null;
}

export const SEARCH_LABELS: Record<SearchKey, string> = {
  domain: 'Domain',
  ip: 'IP address',
  email: 'Email address',
  phone: 'Phone number',
  name: 'Person name',
  asn: 'ASN',
};

/**
 * A country the target itself points to, to pre-fill the optional "where is the subject based?" field. Only what the text
 * says: a phone number's calling code or an email address's country domain. Never a guess from a name.
 */
const CALLING_CODES: [string, string][] = [
  ['+61', 'Australia'], ['+64', 'New Zealand'], ['+44', 'United Kingdom'], ['+353', 'Ireland'], ['+65', 'Singapore'],
  ['+27', 'South Africa'], ['+91', 'India'], ['+49', 'Germany'], ['+33', 'France'], ['+31', 'Netherlands'],
  ['+34', 'Spain'], ['+39', 'Italy'], ['+48', 'Poland'], ['+420', 'Czech Republic'], ['+1', 'United States / Canada'],
];
const COUNTRY_DOMAINS: Record<string, string> = {
  au: 'Australia', nz: 'New Zealand', uk: 'United Kingdom', ie: 'Ireland', sg: 'Singapore', za: 'South Africa',
  in: 'India', de: 'Germany', fr: 'France', nl: 'Netherlands', es: 'Spain', it: 'Italy', pl: 'Poland', cz: 'Czech Republic',
};

export function countryFromTarget(raw: string): string | null {
  const text = (raw ?? '').trim().toLowerCase();
  if (!text) return null;
  if (text.startsWith('+')) {
    const compact = text.replace(/[^\d+]/g, '');
    // longest calling code first, so +353 is not read as +3
    const hit = [...CALLING_CODES].sort((a, b) => b[0].length - a[0].length).find(([code]) => compact.startsWith(code));
    return hit ? hit[1] : null;
  }
  const email = text.match(/^[^\s@]+@[^\s@]+\.([a-z]{2})$/);
  return email && COUNTRY_DOMAINS[email[1]] ? COUNTRY_DOMAINS[email[1]] : null;
}
