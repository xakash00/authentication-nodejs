import { config } from "../config/test-config";

const nodemailer = require('nodemailer');

interface EmailOptions {
    to: string;
    subject: string;
    html: string;
}


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

export const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: config.EMAIL_USER!,
        pass: config.EMAIL_PASS!
    }
});

export const sendEmail = async (options: EmailOptions) => {
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            ...options
        });
    } catch (error) {
        console.error('Error sending email:', error);
    }
};

export function calculateLeaveDays(start: Date, end: Date): number {
    const timeDiff = end.getTime() - start.getTime();
    return Math.ceil(timeDiff / (1000 * 3600 * 24)) + 1; // +1 to include both start and end days
}