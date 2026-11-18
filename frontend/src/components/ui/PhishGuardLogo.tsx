import React from 'react';

interface PhishGuardLogoProps {
  size?: number;
  className?: string;
}

/**
 * PhishGuard premium logo — fishhook inside a shield
 * Uses inline SVG for crisp rendering at any size.
 */
const PhishGuardLogo: React.FC<PhishGuardLogoProps> = ({ size = 36, className = '' }) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 48 48"
      fill="none"
      width={size}
      height={size}
      className={className}
      aria-label="PhishGuard logo"
    >
      <defs>
        <linearGradient id="pg-hookGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#FF4040" />
          <stop offset="100%" stopColor="#B91C1C" />
        </linearGradient>
        <linearGradient id="pg-shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#1a0a0a" />
          <stop offset="100%" stopColor="#0d0505" />
        </linearGradient>
        <filter id="pg-glow" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="1.2" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>

      {/* Shield base */}
      <path
        d="M24 3L6 10v12c0 10.5 7.6 20.3 18 22.8C34.4 42.3 42 32.5 42 22V10L24 3z"
        fill="url(#pg-shieldGrad)"
        stroke="url(#pg-hookGrad)"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />

      {/* Inner border glow */}
      <path
        d="M24 6.5L9 12.5v9.5c0 9 6.5 17.3 15 19.5C33.5 39.3 39 31 39 22v-9.5L24 6.5z"
        fill="none"
        stroke="rgba(239,68,68,0.18)"
        strokeWidth="0.8"
      />

      {/* Hook vertical stem */}
      <path
        d="M24 13 L24 28"
        stroke="url(#pg-hookGrad)"
        strokeWidth="2.5"
        strokeLinecap="round"
        filter="url(#pg-glow)"
      />

      {/* Hook curve — smooth J bend */}
      <path
        d="M24 28 C24 33, 18 35, 18 31 C18 28.5, 20.5 27.5, 22 29"
        stroke="url(#pg-hookGrad)"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
        filter="url(#pg-glow)"
      />

      {/* Barb tip */}
      <path
        d="M22 29 L19.5 27"
        stroke="url(#pg-hookGrad)"
        strokeWidth="2"
        strokeLinecap="round"
      />

      {/* Eye ring */}
      <circle
        cx="24"
        cy="12"
        r="2.2"
        stroke="url(#pg-hookGrad)"
        strokeWidth="2"
        fill="none"
        filter="url(#pg-glow)"
      />

      {/* Eye dot */}
      <circle cx="24" cy="12" r="0.8" fill="#FF4040" opacity="0.9" />
    </svg>
  );
};

export default PhishGuardLogo;
