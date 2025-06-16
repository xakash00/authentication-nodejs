import { Request, Response, NextFunction } from 'express';
import User, { IToken } from '../models/AuthModels';
import { AuthenticatedRequest } from '../middlewares/auth';
import PasswordResetToken from '../models/PasswrodResetModel';
import { config } from '../config/test-config';
import { generateOTP, transporter } from '../utlis/fileHelper';

const jwt = require("jsonwebtoken")
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer')

const registerForm = (req: Request, res: Response): void => {
    res.render('register');
};

const loginForm = (req: Request, res: Response): void => {
    res.render('login');
};



const registerNewUser = async (req: Request, res: Response): Promise<void> => {
    try {
        const { user_name, email, password, role } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(409).json({ message: 'Email already exists.' });
            return;
        }

        const registerUser = new User({
            user_name,
            email,
            password,
            role: role === 'manager' ? 'manager' : 'employee', // default fallback
            slug: user_name.toLowerCase().replace(/\s+/g, '-')
        });

        await registerUser.save();

        res.status(201).json({ message: 'Registration successful.' });
    } catch (err) {
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
};

const login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            res.status(401).json({ message: "Invalid Credentials." });
            return;
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            res.status(401).json({ message: 'Invalid Credentials.' });
            return;
        }

        const token = await user.generateAuthToken();

        res.cookie("utoken", token, {
            expires: new Date(Date.now() + 600000),
            httpOnly: true,
        });

        res.status(201).json({
            message: 'Login successful.',
            accessToken: token,
        });

    } catch (e) {
        console.error('Login error:', e);
        res.status(500).json({
            message: 'Something went wrong.',
        });
    }
}



const logout = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        if (!req.user || !req.token) {
            res.status(400).json({ message: 'No user or token found in request' });
        }
        req.user.tokens = req.user.tokens.filter((t: { token: string }) => t.token !== req.token);

        await req.user.save();

        res.clearCookie('utoken');

        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        next(error)
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

const logoutAll = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        if (!req.user || !req.token) {
            res.status(400).json({ message: 'No user or token found in request' });
            return
        }
        req.user.tokens = []

        await req.user.save();

        res.clearCookie('utoken');

        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        next(error)
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

const getUserDetails = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { slug } = req.params;
        console.log(req.params)
        if (req?.user.slug.toString() !== slug) {
            res.status(403).json({ message: 'Forbidden. You are not allowed to access this resource.' });
            return
        }
        res.status(200).json({ data: { user_name: req.user.user_name, email: req.user.email, role: req.user.role } });


    } catch (err) {
        console.error('Get User Error:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

const deleteUser = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        const { slug } = req.params;

        const userToDelete = await User.findOne({ slug });
        if (!userToDelete) {
            res.status(404).json({ message: 'User not found' });
            return;
        }

        const isSelf = req.user.slug === slug;
        const isManager = req.user.role === 'manager';

        // Only allow if self or manager deleting employee
        if (!isSelf && (!isManager || userToDelete.role === 'manager')) {
            res.status(403).json({ message: 'Forbidden: Not authorized to delete this user' });
            return
        }

        await userToDelete.deleteOne();
        res.status(200).json({ message: 'User deleted successfully' });

    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
};


const updateUserDetails = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        const { slug } = req.params;

        const user = await User.findOne({ slug });
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }

        const isSelf = req.user.slug === slug;
        const isManager = req.user.role === 'manager';

        // Prevent manager from updating another manager
        if (!isSelf && (!isManager || user.role === 'manager')) {
            res.status(403).json({ message: 'Forbidden: Not authorized to update this user' });
            return;
        }

        const protectedFields = ['email', 'password', 'role']; // prevent changing role here
        const updates = Object.keys(req.body);
        const hasInvalidField = updates.some(field => protectedFields.includes(field));
        if (hasInvalidField) {
            res.status(400).json({ message: 'You cannot update email, password, or role via this route' });
            return;
        }

        updates.forEach(field => {
            if (req.body[field] === null) {
                user.set(field, undefined);
            } else {
                user.set(field, req.body[field]);
            }
        });

        await user.save();
        res.status(200).json({ message: 'User updated successfully' });

    } catch (err) {
        console.error('Update error:', err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
};


const requestPasswordReset = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }

        // Generate OTP
        const otp = generateOTP();

        // Remove any existing OTP tokens for this user
        await PasswordResetToken.deleteMany({ userId: user._id });

        // Save new OTP
        const resetToken = new PasswordResetToken({
            userId: user._id,
            token: otp,
            expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
        });
        await resetToken.save();

        const mailOptions = {
            from: config.EMAIL_USER!,
            to: email,
            subject: 'Your Password Reset OTP',
            html: `
        <div style="background-color: #ECFDF5; color: #000; font-family: Arial, sans-serif; padding: 40px; text-align: center;">
          <h2>Password Reset Request</h2>
          <p>Your OTP for password reset is:</p>
          <h1 style="letter-spacing: 4px; margin: 20px 0;">${otp}</h1>
          <p>This OTP will expire in 15 minutes.</p>
          <p>If you didn’t request this, you can ignore this email.</p>
        </div>`,
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: "OTP sent to your email.", email });
    } catch (err) {
        console.error('Request Password Reset Error:', err);
        res.status(500).json({ message: 'Server error' });
    }
};


const resetPassword = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, otp, newPassword } = req.body;

        if (!email || !otp || !newPassword) {
            res.status(400).json({ message: 'Email, OTP, and new password are required.' });
            return;
        }

        // Find the reset token
        const resetTokenDoc = await PasswordResetToken.findOne({ token: otp }).populate('userId');
        if (!resetTokenDoc) {
            res.status(400).json({ message: 'Invalid or expired OTP.' });
            return;
        }

        // Check expiration
        if (resetTokenDoc.expiresAt < new Date()) {
            await resetTokenDoc.deleteOne();
            res.status(400).json({ message: 'OTP has expired.' });
            return;
        }

        // Ensure email matches the user
        const user = await User.findById(resetTokenDoc.userId);
        if (!user || user.email !== email) {
            res.status(404).json({ message: 'User not found or email mismatch.' });
            return;
        }

        // Update password and clear tokens
        user.password = newPassword;
        user.tokens = [];
        await user.save();

        // Delete the reset token
        await resetTokenDoc.deleteOne();

        res.status(200).json({ message: 'Password has been reset. Please log in again.' });
    } catch (err) {
        console.error('Reset Password Error:', err);
        res.status(500).json({ message: 'Server error' });
    }
};



export { login, loginForm, logout, registerForm, registerNewUser, logoutAll, deleteUser, getUserDetails, updateUserDetails, requestPasswordReset, resetPassword }