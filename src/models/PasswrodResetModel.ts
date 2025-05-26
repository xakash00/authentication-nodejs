import mongoose, { Schema, Document } from 'mongoose';

export interface IPasswordResetToken extends Document {
    userId: mongoose.Types.ObjectId;
    token: string;
    expiresAt: Date;
}

const PasswordResetTokenSchema = new Schema<IPasswordResetToken>({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true },
    expiresAt: { type: Date, required: true }
});

const PasswordResetToken = mongoose.model<IPasswordResetToken>('PasswordResetToken', PasswordResetTokenSchema);
export default PasswordResetToken;
