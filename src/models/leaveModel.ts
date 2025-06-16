import mongoose, { Document, Model, Schema, Types } from 'mongoose';
import { IUser, PopulatedUser } from './AuthModels';
import { sendEmail } from '../utlis/fileHelper';

export enum LeaveStatus {
    PENDING = 'pending',
    APPROVED = 'approved',
    REJECTED = 'rejected'
}

export enum LeaveType {
    ANNUAL = 'annual',
    SICK = 'sick',
    MATERNITY = 'maternity',
    PATERNITY = 'paternity',
    UNPAID = 'unpaid'
}

export interface ILeave extends Document {
    employee: Types.ObjectId | PopulatedUser;
    managerSlug: string;
    startDate: Date;
    endDate: Date;
    reason: string;
    status: LeaveStatus;
    type: LeaveType;
    createdAt: Date;
    updatedAt: Date;
}

export interface ILeaveMethods {
    notifyManager(): Promise<void>;
    notifyEmployee(action: 'approved' | 'rejected'): Promise<void>;
}

type LeaveModel = Model<ILeave, {}, ILeaveMethods>;

const LeaveSchema = new Schema<ILeave, LeaveModel, ILeaveMethods>({
    employee: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    managerSlug: { type: String, ref: 'User' },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    reason: { type: String, required: true },
    status: {
        type: String,
        enum: Object.values(LeaveStatus),
        default: LeaveStatus.PENDING
    },
    type: {
        type: String,
        enum: Object.values(LeaveType),
        required: true
    },
}, { timestamps: true });

// Email notification to manager when leave is requested
LeaveSchema.methods.notifyManager = async function () {
    const leave = this as ILeave;
    const manager = await mongoose.model('User').findOne({ slug: leave.managerSlug });
    const employee = await mongoose.model('User').findById(leave.employee);

    if (manager && employee) {
        await sendEmail({
            to: manager.email,
            subject: 'New Leave Request',
            html: `
        <p>Hello ${manager.user_name},</p>
        <p>${employee.user_name} has requested leave from ${leave.startDate.toDateString()} to ${leave.endDate.toDateString()}.</p>
        <p>Reason: ${leave.reason}</p>
        <p>Please review this request in your dashboard.</p>
      `
        });
    }
};

// Email notification to employee when leave is approved/rejected
LeaveSchema.methods.notifyEmployee = async function (action: 'approved' | 'rejected') {
    const leave = this as ILeave;
    const manager = await mongoose.model('User').findOne({ slug: leave.managerSlug });
    const employee = await mongoose.model('User').findById(leave.employee);

    if (manager && employee) {
        await sendEmail({
            to: employee.email,
            subject: `Leave Request ${action}`,
            html: `
        <p>Hello ${employee.user_name},</p>
        <p>Your leave request from ${leave.startDate.toDateString()} to ${leave.endDate.toDateString()} has been ${action} by ${manager.user_name}.</p>
        ${action === 'rejected' ? `<p>Reason: ${leave.reason}</p>` : ''}
      `
        });
    }
};

// Update user's leaves when leave is approved
LeaveSchema.post('save', async function (doc: ILeave) {
    if (doc.status === LeaveStatus.APPROVED && doc.isModified('status')) {
        const User = mongoose.model('User');
        const employee = await User.findById(doc.employee);

        if (employee) {
            const leaveDays = calculateLeaveDays(doc.startDate, doc.endDate);

            // Deduct from leaves left
            employee.leavesLeft = (employee.leavesLeft || 0) - leaveDays;
            await employee.save();
        }
    }
});

function calculateLeaveDays(startDate: Date, endDate: Date): number {
    const diffTime = Math.abs(endDate.getTime() - startDate.getTime());
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1; // +1 to include both start and end dates
}

export const Leave = mongoose.model<ILeave, LeaveModel>('Leave', LeaveSchema);