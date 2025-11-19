import React from "react";

const Brackets = () => {
  return (
    <>
      <span 
        className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 pointer-events-none" 
        style={{ 
          borderColor: 'var(--pleroma-accent)', 
          boxShadow: '0 0 5px color-mix(in srgb, var(--pleroma-accent) 50%, transparent)' 
        }}
      ></span>
      <span 
        className="absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 pointer-events-none" 
        style={{ 
          borderColor: 'var(--pleroma-accent)', 
          boxShadow: '0 0 5px color-mix(in srgb, var(--pleroma-accent) 50%, transparent)' 
        }}
      ></span>
      <span 
        className="absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 pointer-events-none" 
        style={{ 
          borderColor: 'var(--pleroma-accent)', 
          boxShadow: '0 0 5px color-mix(in srgb, var(--pleroma-accent) 50%, transparent)' 
        }}
      ></span>
      <span 
        className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 pointer-events-none" 
        style={{ 
          borderColor: 'var(--pleroma-accent)', 
          boxShadow: '0 0 5px color-mix(in srgb, var(--pleroma-accent) 50%, transparent)' 
        }}
      ></span>
    </>
  );
};

export default Brackets;
