import mongoose, { Document, Model, Schema, Types, model } from 'mongoose';
import slugify from 'slugify';
import { config } from '../config/test-config';
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

export enum UserRole {
    MANAGER = 'manager',
    EMPLOYEE = 'employee'
}

export interface IToken {
    token: string;
    type: 'access';
    expiresAt: Date;
}

export type PopulatedUser = {
    user_name: string;
    email: string;
    // Add other fields you need to access
};

export interface IManager extends Document {
    user_name: string;
    email: string;
}

export interface IUser extends Document {
    user_name: string;
    email: string;
    password: string;
    role: UserRole;
    department: string;
    manager?: string;
    tokens: IToken[];
    totalLeaves?: number;
    leavesLeft?: number;
    leavesTaken?: number;
    leaveTypes?: {
        annual: number;
        sick: number;
        maternity?: number;
        paternity?: number;
        unpaid?: number;
    };
    leaveHistory?: Types.ObjectId[];
    slug: string;
    generateAuthToken(): Promise<string>;
}

interface IUserModel extends Model<IUser> {

}

const UserSchema = new Schema<IUser, IUserModel>({
    user_name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: Object.values(UserRole), required: true },
    department: { type: String },
    manager: { type: String, ref: 'User' },
    tokens: [{ type: Object }],
    totalLeaves: { type: Number, default: 0 },
    leavesLeft: { type: Number, default: 0 },
    leavesTaken: { type: Number, default: 0 },
    leaveTypes: {
        annual: { type: Number, default: 0 },
        sick: { type: Number, default: 0 },
        maternity: { type: Number, default: 0 },
        paternity: { type: Number, default: 0 },
        unpaid: { type: Number, default: 0 }
    },
    leaveHistory: [{ type: Schema.Types.ObjectId, ref: 'Leave' }],
    slug: { type: String, unique: true }
}, { timestamps: true });

UserSchema.methods.generateAuthToken = async function (): Promise<String> {
    const token = jwt.sign(
        { _id: this._id.toString() },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
    );

    this.tokens = this.tokens.concat({ token });
    await this.save();
    return token;
}

UserSchema.pre('save', async function (next) {
    const user = this as any;

    if (user.isModified('name') || user.isNew) {
        let baseSlug = slugify(user.user_name, { lower: true, strict: true });
        let slug = baseSlug;
        let count = 1;
        while (await mongoose.models.User.findOne({ slug })) {
            slug = `${baseSlug}-${count++}`;
        }

        user.slug = slug;
    }

    next();
});

UserSchema.pre<IUser>("save", async function (next) {
    if (this.isModified("password")) {
        this.password = await bcrypt.hash(this.password, config.SALT_ROUNDS);
    }
    next();
});

const User = model<IUser, IUserModel>('User', UserSchema);
export default User;