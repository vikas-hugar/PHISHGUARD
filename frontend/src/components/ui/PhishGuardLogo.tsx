import React from 'react';

interface PhishGuardLogoProps {
  size?: number;
  className?: string;
  /** Override fill colour — defaults to currentColor so CSS colour controls it */
  color?: string;
}

/**
 * PhishGuard logo mark — fish silhouette forming the letter "P" with a fishhook below.
 * Served as an <img> pointing at the public SVG asset for crisp rendering at any size.
 */
const PhishGuardLogo: React.FC<PhishGuardLogoProps> = ({
  size = 36,
  className = '',
}) => {
  return (
    <img
      src="/phishguard-logo.svg"
      alt="PhishGuard"
      width={size}
      height={size}
      className={className}
      style={{ objectFit: 'contain' }}
    />
  );
};

export default PhishGuardLogo;
