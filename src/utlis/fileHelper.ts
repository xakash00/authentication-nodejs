
export const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${days}d ${hours}h ${mins}m ${secs}s`;
};

export const generateOTP = (): string => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};