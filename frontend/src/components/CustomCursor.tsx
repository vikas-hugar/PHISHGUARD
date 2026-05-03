import React, { useEffect, useState } from 'react';
import { motion, useMotionValue, useSpring } from 'framer-motion';

const CustomCursor: React.FC = () => {
    const [isHovered, setIsHovered] = useState(false);
    const [isClicked, setIsClicked] = useState(false);

    const mouseX = useMotionValue(-100);
    const mouseY = useMotionValue(-100);

    // Spring configuration for smooth trailing effect
    const springConfig = { damping: 25, stiffness: 250, mass: 0.5 };
    const cursorX = useSpring(mouseX, springConfig);
    const cursorY = useSpring(mouseY, springConfig);

    // Outer ring config (slower spring)
    const ringConfig = { damping: 30, stiffness: 150, mass: 0.8 };
    const ringX = useSpring(mouseX, ringConfig);
    const ringY = useSpring(mouseY, ringConfig);

    useEffect(() => {
        const moveCursor = (e: MouseEvent) => {
            mouseX.set(e.clientX);
            mouseY.set(e.clientY);
        };

        const handleMouseDown = () => setIsClicked(true);
        const handleMouseUp = () => setIsClicked(false);

        // Track when hovering over clickable elements
        const handleMouseOver = (e: MouseEvent) => {
            const target = e.target as HTMLElement;
            // Check if element or its parent is clickable
            const isClickable = target.closest('a, button, input, [role="button"], .interactive-element');
            setIsHovered(!!isClickable);
        };

        window.addEventListener('mousemove', moveCursor);
        window.addEventListener('mousedown', handleMouseDown);
        window.addEventListener('mouseup', handleMouseUp);
        window.addEventListener('mouseover', handleMouseOver);

        return () => {
            window.removeEventListener('mousemove', moveCursor);
            window.removeEventListener('mousedown', handleMouseDown);
            window.removeEventListener('mouseup', handleMouseUp);
            window.removeEventListener('mouseover', handleMouseOver);
        };
    }, [mouseX, mouseY]);

    // Don't render cursor on small touch screens
    if (typeof window !== 'undefined' && window.innerWidth <= 768) {
        return null;
    }

    return (
        <div className="pointer-events-none fixed inset-0 z-[9999]">
            {/* Inner dot */}
            <motion.div
                className="absolute top-0 left-0 rounded-full bg-primary"
                style={{
                    x: cursorX,
                    y: cursorY,
                    translateX: '-50%',
                    translateY: '-50%',
                    width: '8px',
                    height: '8px',
                    boxShadow: '0 0 10px rgba(0,174,239,0.8)'
                }}
                animate={{
                    scale: isClicked ? 0.5 : isHovered ? 0 : 1,
                    opacity: isHovered ? 0 : 1
                }}
                transition={{ duration: 0.15 }}
            />
            
            {/* Outer ring */}
            <motion.div
                className="absolute top-0 left-0 rounded-full border border-primary/50 mix-blend-screen backdrop-blur-sm"
                style={{
                    x: ringX,
                    y: ringY,
                    translateX: '-50%',
                    translateY: '-50%',
                    width: '40px',
                    height: '40px',
                    background: isHovered ? 'rgba(0,174,239,0.1)' : 'transparent',
                }}
                animate={{
                    scale: isClicked ? 0.8 : isHovered ? 1.5 : 1,
                    borderColor: isHovered ? 'rgba(0,255,178,0.5)' : 'rgba(0,174,239,0.3)',
                    boxShadow: isHovered 
                        ? '0 0 20px rgba(0,255,178,0.2)' 
                        : '0 0 0px transparent'
                }}
                transition={{ duration: 0.2 }}
            />
        </div>
    );
};

export default CustomCursor;
