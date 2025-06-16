import mongoose, { Document, Model, Schema, Types, model } from 'mongoose';
import slugify from 'slugify';
import { config } from '../config/test-config';
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

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
    slug: string;
    user_name: string;
    email: string;
    password: string;
    role: 'manager' | 'employee';
    tokens: IToken[];
    generateAuthToken(): Promise<string>;
    removeExpiredTokens(): Promise<void>;
    manager?: Types.ObjectId;
    totalLeaves: number;
    leavesLeft: number;
    leaveTypes: {
        annual: number;
        sick: number;
        maternity: number;
        paternity: number;
        unpaid: number;
    };
}


interface IUserModel extends Model<IUser> {

}

const UserSchema = new Schema<IUser, IUserModel>({
    slug: { type: String, unique: true },
    user_name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    role: { type: String, enum: ['manager', 'employee'], default: 'employee', required: true },
    manager: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    },
    password: { type: String, required: true },
    tokens: [{
        token: { type: String, required: true },
        type: { type: String, enum: ['access'], default: 'access' },
        expiresAt: { type: Date }
    }],
    totalLeaves: { type: Number, default: 20 },
    leavesLeft: { type: Number, default: 20 },
    leaveTypes: {
        annual: { type: Number, default: 20 },
        sick: { type: Number, default: 10 },
        maternity: { type: Number, default: 90 },
        paternity: { type: Number, default: 14 },
        unpaid: { type: Number, default: 0 }
    }
}, { strict: false });



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