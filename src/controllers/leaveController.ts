import mongoose, { Types } from 'mongoose';
import { Request, Response } from 'express';
import { IUser, PopulatedUser } from '../models/AuthModels';
import { Leave, LeaveStatus } from '../models/leaveModel';
import { calculateLeaveDays } from '../utlis/fileHelper';

// Employee requests leave
export const requestLeave = async (req: any, res: Response) => {
    try {
        // 1. Validate input
        const { startDate, endDate, reason, type } = req.body;
        if (!startDate || !endDate || !reason || !type) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // 2. Get authenticated user
        const employee = req.user as IUser;
        if (!employee.manager) {
            return res.status(400).json({ message: 'You must have a manager assigned' });
        }

        // 3. Verify dates
        if (new Date(startDate) >= new Date(endDate)) {
            return res.status(400).json({ message: 'End date must be after start date' });
        }

        // Get manager details
        const manager = await mongoose.model('User').findById(employee.manager);
        if (!manager) {
            return res.status(400).json({ message: 'Manager not found' });
        }

        // 4. Create and save leave
        const leave = await Leave.create({
            employee: employee._id,
            managerSlug: manager.slug,
            startDate,
            endDate,
            reason,
            type,
            status: LeaveStatus.PENDING
        });

        // 5. Notify manager
        await leave.notifyManager();

        res.status(201).json(leave);
    } catch (error) {
        console.log(error)
        res.status(500).json({
            message: 'Error requesting leave',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// Manager approves/rejects leave
export const reviewLeave = async (req: any, res: Response) => {
    try {
        const { leaveId, action } = req.body;
        const manager = req.user as IUser;

        // 1. Find the leave request
        const leave = await Leave.findById(leaveId);
        if (!leave) {
            return res.status(404).json({ message: 'Leave not found' });
        }

        // 2. Verify manager
        if (leave.managerSlug !== manager.slug) {
            return res.status(403).json({
                message: 'Only the assigned manager can review this leave'
            });
        }

        // 3. Update leave status
        leave.status = action === 'approve'
            ? LeaveStatus.APPROVED
            : LeaveStatus.REJECTED;

        await leave.save();
        await leave.notifyEmployee(action === 'approve' ? 'approved' : 'rejected');

        res.status(200).json(leave);
    } catch (error) {
        res.status(500).json({
            message: 'Error reviewing leave',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// Manager updates employee's leave balance
export const updateLeaveBalance = async (req: any, res: Response) => {
    try {
        const { employeeId, leaveType, days } = req.body;
        const manager = req.user as IUser;

        // 1. Find the employee
        const employee = await mongoose.model('User').findById(employeeId);
        if (!employee) {
            return res.status(404).json({ message: 'Employee not found' });
        }

        // 2. Verify the requesting user is the employee's actual manager
        const employeeManagerId = employee.manager as Types.ObjectId;
        const currentManagerId = manager._id as Types.ObjectId;

        if (!employeeManagerId || !employeeManagerId.equals(currentManagerId)) {
            return res.status(403).json({
                message: 'Only the assigned manager can update leave balances'
            });
        }

        // 3. Validate leave type exists if specified
        if (leaveType && !employee.leaveTypes?.[leaveType]) {
            return res.status(400).json({
                message: 'Invalid leave type',
                validTypes: Object.keys(employee.leaveTypes || {})
            });
        }

        // 4. Update the specific leave type or general balance
        if (leaveType) {
            employee.leaveTypes[leaveType] = days;

            // For annual leaves, update the general balance too
            if (leaveType === 'annual') {
                employee.totalLeaves = days;
                employee.leavesLeft = days;
            }
        } else {
            // Update general balance
            employee.totalLeaves = days;
            employee.leavesLeft = days;
        }

        // 5. Save and respond
        await employee.save();
        res.status(200).json({
            message: 'Leave balance updated successfully',
            employee: {
                id: employee._id,
                leaveTypes: employee.leaveTypes,
                totalLeaves: employee.totalLeaves,
                leavesLeft: employee.leavesLeft
            }
        });

    } catch (error) {
        res.status(500).json({
            message: 'Error updating leave balance',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// Get all leaves for logged-in employee
export const getEmployeeLeaves = async (req: any, res: Response) => {
    try {
        const employee = req.user as IUser;
        const leaves = await Leave.find({ employee: employee._id });
        res.status(200).json(leaves);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching leaves', error });
    }
};

// Get all pending leaves for manager's team
export const getManagerPendingLeaves = async (req: any, res: Response) => {
    try {
        const manager = req.user as IUser;
        const leaves = await Leave.find({
            manager: manager._id,
            status: LeaveStatus.PENDING
        }).populate('employee', 'user_name email');

        res.status(200).json(leaves);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching pending leaves', error });
    }
};

export const getApprovedLeaves = async (req: Request, res: Response) => {
    try {
        const { startDate, endDate, department } = req.query;

        const query: any = {
            status: LeaveStatus.APPROVED
        };

        if (startDate && endDate) {
            query.startDate = { $gte: new Date(startDate as string) };
            query.endDate = { $lte: new Date(endDate as string) };
        }

        const leaves = await Leave.find(query)
            .select('startDate endDate reason type employee manager')
            .populate<{ employee: PopulatedUser, manager: PopulatedUser }>(['employee', 'manager'])
            .sort({ startDate: 1 });

        // Type-safe transformation
        const response = leaves.map(leave => {
            const getUsername = (field: Types.ObjectId | PopulatedUser): string => {
                return field instanceof Types.ObjectId ? '' : field.user_name;
            };

            return {
                id: leave._id,
                startDate: leave.startDate,
                endDate: leave.endDate,
                reason: leave.reason,
                type: leave.type,
                employee: getUsername(leave.employee),
                manager: getUsername(leave.manager)
            };
        });

        res.status(200).json({
            count: leaves.length,
            leaves: response
        });

    } catch (error) {
        res.status(500).json({
            message: 'Error fetching approved leaves',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// Enhanced version with filtering
export const getUserOwnLeaves = async (req: any, res: Response) => {
    try {
        const user = req.user as IUser;
        const { status, year, type } = req.query;

        // Build query
        const query: any = { employee: user._id };

        // Add status filter if provided
        if (status) {
            query.status = status;
        }

        // Add year filter if provided
        if (year) {
            query.startDate = {
                $gte: new Date(`${year}-01-01`),
                $lte: new Date(`${year}-12-31`)
            };
        }

        // Add leave type filter if provided
        if (type) {
            query.type = type;
        }

        const leaves = await Leave.find(query)
            .sort({ startDate: -1 })
            .populate('managerSlug', 'user_name slug email');

        res.status(200).json({
            success: true,
            count: leaves.length,
            data: leaves.map(leave => ({
                id: leave._id,
                startDate: leave.startDate,
                endDate: leave.endDate,
                days: calculateLeaveDays(leave.startDate, leave.endDate),
                type: leave.type,
                status: leave.status,
                reason: leave.reason,
                manager: leave.managerSlug
            }))
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error fetching your leaves',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// GET /user/leave-data - Get all leave data
// GET /user/leave-data?year=2023 - Get leave data for 2023 only
export const getUserLeaveData = async (req: any, res: Response) => {
    try {
        const user = req.user as IUser;

        // Get the populated user document with leave data
        const userWithLeaveData = await mongoose.model('User').findById(user._id)
            .select('totalLeaves leavesLeft leavesTaken leaveTypes leaveHistory')
            .populate({
                path: 'leaveHistory',
                select: 'startDate endDate type status reason',
                options: { sort: { startDate: -1 }, limit: 10 } // Last 10 leaves
            });

        if (!userWithLeaveData) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Calculate leave utilization
        const utilization = {
            annual: {
                allocated: userWithLeaveData.leaveTypes.annual,
                used: await Leave.countDocuments({
                    employee: user._id,
                    type: 'annual',
                    status: LeaveStatus.APPROVED
                })
            },
            sick: {
                allocated: userWithLeaveData.leaveTypes.sick,
                used: await Leave.countDocuments({
                    employee: user._id,
                    type: 'sick',
                    status: LeaveStatus.APPROVED
                })
            },
            // Add other leave types as needed
        };

        res.status(200).json({
            success: true,
            data: {
                summary: {
                    totalLeaves: userWithLeaveData.totalLeaves,
                    leavesLeft: userWithLeaveData.leavesLeft,
                    leavesTaken: userWithLeaveData.leavesTaken
                },
                leaveTypes: userWithLeaveData.leaveTypes,
                utilization,
                recentLeaves: userWithLeaveData.leaveHistory
            }
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error fetching user leave data',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};