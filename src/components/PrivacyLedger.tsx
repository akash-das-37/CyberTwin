import type { PrivacyLedger as PrivacyLedgerData } from '../types';

interface PrivacyLedgerProps {
  ledger?: PrivacyLedgerData;
}

export function PrivacyLedger({ ledger }: PrivacyLedgerProps) {
  if (!ledger) return null;

  return (
    <section className="privacy-ledger" aria-label="Privacy Ledger">
      <div className="privacy-ledger-header">
        <div>
          <p className="privacy-ledger-kicker">Privacy Ledger</p>
          <h3>Stored in chrome.storage.local</h3>
        </div>
        <strong className="privacy-ledger-status">
          Raw body saved: {ledger.rawEmailBodyStored ? 'Yes' : 'No'}
        </strong>
      </div>
      <div className="privacy-ledger-metrics">
        <div>
          <span>Body storage</span>
          <strong>{ledger.storedBodyText === 'scrubbed_preview_150_chars' ? 'Scrubbed preview' : ledger.storedBodyText}</strong>
        </div>
        <div>
          <span>Preview length</span>
          <strong>{ledger.scrubbedPreviewLength}/150 chars</strong>
        </div>
        <div>
          <span>Link storage</span>
          <strong>Domain summaries only</strong>
        </div>
      </div>
      <div className="privacy-ledger-columns">
        <div>
          <span>Stored fields</span>
          <ul>
            {ledger.storedFields.map((field) => (
              <li key={field}>{field}</li>
            ))}
          </ul>
        </div>
        <div>
          <span>Not stored</span>
          <ul>
            {ledger.strippedFields.map((field) => (
              <li key={field}>{field}</li>
            ))}
          </ul>
        </div>
      </div>
      <p className="privacy-ledger-note">{ledger.note}</p>
    </section>
  );
}

export default PrivacyLedger;
