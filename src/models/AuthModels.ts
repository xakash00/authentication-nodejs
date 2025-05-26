
import mongoose, { Document, Model, Schema, model } from 'mongoose';
import slugify from 'slugify';
import { config } from '../config/test-config';
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

export interface IToken {
    token: unknown;
    type: 'access' | 'refresh';
    expiresAt: Date;
}

export interface IUser extends Document {
    slug: string,
    user_name: string;
    email: string;
    password: string;
    tokens: IToken[];
    generateAuthToken(): Promise<{ accessToken: string; refreshToken: string }>;
    removeExpiredTokens(): Promise<void>;
    resetPasswordToken?: string;
    resetPasswordExpires?: Date;
}


interface IUserModel extends Model<IUser> {

}

const tokenSchema = new Schema<IToken>({
    token: { type: String, required: true },
    type: { type: String, enum: ['access', 'refresh'], required: true },
    expiresAt: { type: Date, required: true }
});

const UserSchema = new Schema<IUser, IUserModel>({
    slug: { type: String, unique: true },
    user_name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    tokens: [tokenSchema]
}, { strict: false });



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

UserSchema.methods.generateAuthToken = async function (): Promise<{ accessToken: string; refreshToken: string }> {
    const user = this;

    const accessToken = user.generateAccessToken();

    const refreshToken = jwt.sign(
        { _id: this._id.toString() },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: config.JWT_REFRESH_EXPRIRES_IN }
    );

    user.tokens = user.tokens.concat([
        {
            token: accessToken,
            type: 'access',
            expiresAt: new Date(Date.now() + 15 * 60 * 1000)
        },
        {
            token: refreshToken,
            type: 'refresh',
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        }
    ]);

    await user.save();

    return { accessToken, refreshToken };
};

const User = model<IUser, IUserModel>('User', UserSchema);
export default User;