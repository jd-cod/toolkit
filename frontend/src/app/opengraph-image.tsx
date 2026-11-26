import { ImageResponse } from 'next/og';

export const alt = 'SysAdmin Toolkit — Network & Security Suite';
export const size = {
  width: 1200,
  height: 630,
};
export const contentType = 'image/png';

export default function OGImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'flex-start',
          justifyContent: 'center',
          backgroundColor: '#07080f',
          backgroundImage:
            'radial-gradient(circle at 25% 25%, rgba(99, 102, 241, 0.25) 0%, transparent 50%), radial-gradient(circle at 75% 75%, rgba(6, 182, 212, 0.2) 0%, transparent 50%)',
          padding: '60px 80px',
          fontFamily: 'sans-serif',
          color: '#f8fafc',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '16px',
            marginBottom: '24px',
          }}
        >
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, #6366f1, #06b6d4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '28px',
            }}
          >
            🛡️
          </div>
          <span style={{ fontSize: '24px', fontWeight: 700, color: '#94a3b8', letterSpacing: '-0.02em' }}>
            SysAdmin Toolkit
          </span>
        </div>

        <h1
          style={{
            fontSize: '56px',
            fontWeight: 800,
            lineHeight: 1.15,
            letterSpacing: '-0.03em',
            margin: '0 0 20px 0',
            maxWidth: '1000px',
            color: '#ffffff',
          }}
        >
          Free SysAdmin &amp; Network Tools
        </h1>

        <p
          style={{
            fontSize: '24px',
            lineHeight: 1.45,
            color: '#94a3b8',
            margin: '0 0 40px 0',
            maxWidth: '920px',
          }}
        >
          Traffic Log Analyzer · DNS &amp; SSL Checkers · WHOIS · ASN Explorer · Subnet &amp; Crontab Calculators
        </p>

        <div
          style={{
            display: 'flex',
            gap: '12px',
          }}
        >
          {['Fast & Local-first', 'Privacy-friendly', 'No Setup Needed', '100% Free'].map((badge) => (
            <div
              key={badge}
              style={{
                backgroundColor: 'rgba(255, 255, 255, 0.08)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: '8px',
                padding: '8px 16px',
                fontSize: '16px',
                color: '#e2e8f0',
                fontWeight: 600,
              }}
            >
              {badge}
            </div>
          ))}
        </div>
      </div>
    ),
    {
      ...size,
    }
  );
}
