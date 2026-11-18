import React from 'react';

interface BrandDividerProps {
  height?: number | string;
  width?: number | string;
  className?: string;
  variant?: 'image' | 'svg';
}

/**
 * Tapered spindle vertical brand divider
 * Thicker in the middle and thin at the top and bottom edges,
 * exactly matching the user's uploaded line image.
 */
export default function BrandDivider({
  height = 26,
  width = 3.5,
  className = '',
  variant = 'image',
}: BrandDividerProps) {
  if (variant === 'image') {
    return (
      <img
        src="/brand-divider-white.png"
        alt="|"
        aria-hidden="true"
        style={{
          height: typeof height === 'number' ? `${height}px` : height,
          width: typeof width === 'number' ? `${width}px` : width,
          objectFit: 'fill',
        }}
        className={`shrink-0 select-none pointer-events-none ${className}`}
      />
    );
  }

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 13 234"
      fill="currentColor"
      preserveAspectRatio="none"
      style={{
        height: typeof height === 'number' ? `${height}px` : height,
        width: typeof width === 'number' ? `${width}px` : width,
      }}
      className={`shrink-0 select-none pointer-events-none ${className}`}
      aria-hidden="true"
    >
      <path d="M 6 0 L 3 4 L 3 9 L 3 14 L 3 19 L 3 23 L 2 28 L 2 33 L 2 38 L 2 42 L 2 47 L 2 52 L 2 57 L 2 61 L 2 66 L 1 71 L 1 76 L 1 80 L 1 85 L 1 90 L 1 95 L 1 99 L 1 104 L 1 109 L 1 114 L 1 118 L 1 123 L 1 128 L 1 133 L 1 137 L 1 142 L 1 147 L 1 152 L 1 156 L 1 161 L 1 166 L 2 171 L 2 175 L 2 180 L 2 185 L 2 190 L 2 194 L 2 199 L 2 204 L 2 209 L 3 213 L 3 218 L 3 223 L 3 228 L 6 233 L 6 233 L 10 228 L 10 223 L 10 218 L 10 213 L 11 209 L 11 204 L 11 199 L 11 194 L 11 190 L 11 185 L 11 180 L 11 175 L 11 171 L 11 166 L 12 161 L 12 156 L 12 152 L 12 147 L 12 142 L 12 137 L 12 133 L 12 128 L 12 123 L 12 118 L 12 114 L 12 109 L 12 104 L 12 99 L 12 95 L 12 90 L 12 85 L 11 80 L 11 76 L 11 71 L 11 66 L 11 61 L 11 57 L 11 52 L 11 47 L 11 42 L 11 38 L 11 33 L 10 28 L 10 23 L 10 19 L 10 14 L 10 9 L 10 4 L 7 0 Z" />
    </svg>
  );
}
