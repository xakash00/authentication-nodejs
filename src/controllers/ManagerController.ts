import { Request, Response } from 'express';
import { AuthenticatedRequest } from '../middlewares/auth';
import User, { IUser } from '../models/AuthModels';
import { transporter } from '../utlis/fileHelper';
import { config } from '../config/test-config';
import mongoose, { Types } from 'mongoose';

export const getManagerDashboard = (req: AuthenticatedRequest, res: Response) => {
    res.status(200).json({
        message: `Welcome Manager: ${req.user.user_name}`,
        accessLevel: req.user.role,
        data: {
            stats: {
                totalEmployees: 42,
                activeProjects: 5,
                revenue: "$1.2M",
            },
        },
    });
};

export const listAllUsersWithRoles = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        const users = await User.find({ _id: { $ne: req.user._id } }, 'user_name email role');
        res.status(200).json({ users });
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const getMyEmployees = async (req: any, res: Response) => {
    try {
        const manager = req.user as IUser;

        // Find all employees where manager field matches current user
        const employees = await mongoose.model('User').find({
            manager: manager._id,
            role: 'employee' // Ensure we only get employees, not other managers
        }).select('-password -tokens'); // Exclude sensitive fields

        if (!employees.length) {
            return res.status(404).json({
                message: 'No employees found under your management'
            });
        }

        res.status(200).json({
            count: employees.length,
            employees: employees.map(emp => ({
                id: emp._id,
                user_name: emp.user_name,
                email: emp.email,
                role: emp.role,
                totalLeaves: emp.totalLeaves,
                leavesLeft: emp.leavesLeft,
                leaveTypes: emp.leaveTypes,
                createdAt: emp.createdAt
            }))
        });

    } catch (error) {
        res.status(500).json({
            message: 'Error fetching employee details',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

export const getMyTeamWithLeaveStats = async (req: any, res: Response) => {
    try {
        const manager = req.user as IUser;

        const employees = await mongoose.model('User').aggregate([
            {
                $match: {
                    manager: manager._id,
                    role: 'employee'
                }
            },
            {
                $lookup: {
                    from: 'leaves',
                    localField: '_id',
                    foreignField: 'employee',
                    as: 'leaves'
                }
            },
            {
                $project: {
                    password: 0,
                    tokens: 0,
                    leaves: {
                        $filter: {
                            input: '$leaves',
                            as: 'leave',
                            cond: { $eq: ['$$leave.status', 'approved'] }
                        }
                    }
                }
            },
            {
                $addFields: {
                    leavesUsed: { $size: '$leaves' },
                    upcomingLeaves: {
                        $size: {
                            $filter: {
                                input: '$leaves',
                                as: 'leave',
                                cond: { $gt: ['$$leave.startDate', new Date()] }
                            }
                        }
                    }
                }
            }
        ]);

        res.status(200).json({
            count: employees.length,
            employees: employees.map(emp => ({
                id: emp._id,
                user_name: emp.user_name,
                email: emp.email,
                totalLeaves: emp.totalLeaves,
                leavesLeft: emp.leavesLeft,
                leavesUsed: emp.leavesUsed,
                upcomingLeaves: emp.upcomingLeaves,
                lastLeave: emp.leaves[0] ? { // Most recent approved leave
                    startDate: emp.leaves[0].startDate,
                    endDate: emp.leaves[0].endDate,
                    type: emp.leaves[0].type
                } : null
            }))
        });
    } catch (error) {
        res.status(500).json({
            message: 'Error fetching team data',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

export const changeUserRole = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        const { slug } = req.params;
        const { role } = req.body;

        if (req.user.role !== 'manager') {
            res.status(403).json({ message: 'Only managers can change roles' });
            return;
        }

        const user = await User.findOne({ slug });
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }

        // ✅ Prevent changing a manager to employee
        if (user.role === 'manager' && role === 'employee') {
            res.status(403).json({ message: 'You cannot change a manager to employee' });
            return;
        }

        if (!['employee', 'manager'].includes(role)) {
            res.status(400).json({ message: 'Invalid role value' });
            return;
        }

        // ✅ Save new role
        user.role = role;
        await user.save();

        // ✅ Email Notification
        const subject = `Your role has been updated to ${role}`;
        const message = `
            Hello ${user.user_name},

            Your role in the system has been updated to: **${role}**.

            If you believe this was a mistake, please contact your administrator.

            Regards,
            HR System
        `;

        await transporter.sendMail({
            from: `"HR Portal" <${config.EMAIL_USER}>`,
            to: user.email,
            subject,
            text: message,
        });

        res.status(200).json({ message: `Role updated to ${role} and email sent.` });

    } catch (err) {
        console.error('Change role error:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

export const assignManager = async (req: Request, res: Response) => {
    try {
        const { employeeSlug, managerSlug } = req.body;

        // Add type assertions
        const employee = await User.findOne({ slug: employeeSlug }).exec() as IUser | null;
        const manager = await User.findOne({ slug: managerSlug }).exec() as IUser | null;

        if (!employee || !manager) {
            return res.status(404).json({ message: 'Employee or Manager not found' });
        }

        if (employee.role !== 'employee') {
            return res.status(400).json({ message: 'Target user is not an employee' });
        }

        if (manager.role !== 'manager') {
            return res.status(400).json({ message: 'Target manager is not valid' });
        }

        // Assign manager's slug
        employee.manager = manager.slug;

        await employee.save();

        return res.status(200).json({
            message: 'Manager assigned successfully',
            data: {
                employee: employee.user_name,
                manager: {
                    user_name: manager.user_name,
                    email: manager.email
                }
            }
        });
    } catch (error) {
        console.error('Assign Manager Error:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
};