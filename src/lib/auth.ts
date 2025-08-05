import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { ObjectId } from 'mongodb';
import { getDatabase } from './mongodb';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';

export interface User {
  _id?: ObjectId;
  email: string;
  nickname: string;
  phone?: string;
  profileImage?: string;
  rating: number;
  role: 'admin' | 'user';
  createdAt: Date;
  updatedAt: Date;
}

export interface UserWithPassword extends User {
  password: string;
}

export interface JWTPayload {
  userId: string;
  email: string;
  role: 'admin' | 'user';
}

export function generateToken(payload: JWTPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

export function verifyToken(token: string): JWTPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET) as JWTPayload;
  } catch (error) {
    console.error('Token verification failed:', error);
    return null;
  }
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}

export function getUserHierarchy(rating: number): 'Común' | 'Distinguido' | 'Élite' {
  if (rating >= 4.5) return 'Élite';
  if (rating >= 3.0) return 'Distinguido';
  return 'Común';
}

export function getHierarchyBorderColor(hierarchy: string): string {
  switch (hierarchy) {
    case 'Élite':
      return 'border-yellow-500';
    case 'Distinguido':
      return 'border-emerald-500';
    default:
      return 'border-gray-400';
  }
}

export async function createAdminUser(): Promise<void> {
  try {
    const db = await getDatabase();
    const usersCollection = db.collection('users');
    
    // Check if admin already exists
    const existingAdmin = await usersCollection.findOne({ role: 'admin' });
    if (existingAdmin) {
      console.log('Admin user already exists');
      return;
    }

    const adminEmail = process.env.ADMIN_EMAIL || 'admin@nosedive.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'AdminTerminator2024!';
    
    const hashedPassword = await hashPassword(adminPassword);
    
    const adminUser: User = {
      email: adminEmail,
      nickname: 'AdminTerminator',
      phone: '+1234567890',
      profileImage: '',
      rating: 5.0,
      role: 'admin',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const adminUserWithPassword: UserWithPassword = {
      ...adminUser,
      password: hashedPassword
    };

    await usersCollection.insertOne(adminUserWithPassword);

    console.log('Admin user created successfully');
  } catch (error) {
    console.error('Failed to create admin user:', error);
    throw error;
  }
}
