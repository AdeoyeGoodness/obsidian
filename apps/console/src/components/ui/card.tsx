import { ReactNode } from 'react';
import Brackets from './brackets';

type CardProps = {
  children: ReactNode;
  className?: string;
  size?: 'small' | 'medium' | 'large';
  glow?: boolean;
  pulse?: boolean;
  hover?: boolean;
};

export function Card({ children, className = '', size = 'medium', glow = false, pulse = false, hover = true }: CardProps) {
  const sizeClasses = {
    small: 'p-4',
    medium: 'p-5',
    large: 'p-6',
  };

  const pulseClass = pulse ? 'neon-pulse' : '';
  const hoverClass = hover ? 'card-lift' : '';

  return (
    <div
      className={`relative border border-gray-800 bg-black/30 ${sizeClasses[size]} ${pulseClass} ${hoverClass} ${className}`}
      style={{
        boxShadow: glow ? '0 0 15px rgba(93, 229, 255, 0.2)' : undefined,
      }}
    >
      <Brackets />
      {children}
    </div>
  );
}

type CardHeaderProps = {
  title: string;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
};

export function CardHeader({ title, icon, action, className = '' }: CardHeaderProps) {
  return (
    <div className={`flex items-center justify-between mb-4 ${className}`}>
      <div className="flex items-center gap-3">
        {icon && <span className="text-cyan-400">{icon}</span>}
        <p className="uppercase text-[11px] tracking-[0.3em] text-gray-500">{title}</p>
      </div>
      {action}
    </div>
  );
}

type StatCardProps = {
  label: string;
  value: string | number;
  hint?: string;
  trend?: 'up' | 'down' | 'neutral';
  sparkline?: ReactNode;
};

export function StatCard({ label, value, hint, trend, sparkline }: StatCardProps) {
  const trendColor = trend === 'up' ? 'text-emerald-400' : trend === 'down' ? 'text-red-400' : 'text-gray-400';
  
  return (
    <Card size="small" className="relative">
      <p className="uppercase text-[10px] tracking-[0.35em] text-gray-500">{label}</p>
      <div className="mt-2 flex items-end justify-between">
        <p className="text-2xl font-semibold text-white">{value}</p>
        {sparkline && <div className="mb-1">{sparkline}</div>}
      </div>
      {hint && <p className="mt-1 text-[11px] text-gray-500">{hint}</p>}
      {trend && (
        <div className={`absolute top-2 right-2 text-xs ${trendColor}`}>
          {trend === 'up' ? '↑' : trend === 'down' ? '↓' : '—'}
        </div>
      )}
    </Card>
  );
}
