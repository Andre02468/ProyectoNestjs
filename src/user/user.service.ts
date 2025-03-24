import {Injectable, UnauthorizedException, ConflictException, NotFoundException} from '@nestjs/common';
  import { User, UserServiceInterface } from './interfaces/user.interface';
  import {CreateUserDto, UpdateUserDto, LoginDto, ChangePasswordDto } from './dto/user.dto';
  import * as nodemailer from 'nodemailer';
  import { UserDocument, UserModel } from './schemas/user.schema';
  import { InjectModel } from '@nestjs/mongoose';
  import { JwtService } from '@nestjs/jwt';
  import { Model } from 'mongoose';
  import * as bcrypt from 'bcrypt';
  import { randomInt } from 'crypto';
  
  @Injectable()
  export class UserService implements UserServiceInterface {
    private transporter: nodemailer.Transporter;
  
    constructor(
      @InjectModel(UserModel.name) private userModel: Model<UserDocument>,
      private jwtService: JwtService,
    ) {
      this.transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT || '587'),
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });
    }
  
    async create(createUserDto: CreateUserDto): Promise<User> {
      const usuarioExistente = await this.userModel.findOne({
        email: createUserDto.email,
      });
      if (usuarioExistente) {
        throw new ConflictException('El email ya se encuentra registrado');
      }
  
      const contraseñaEncriptada = await bcrypt.hash(createUserDto.password, 10);
      const codigoVerificacion = randomInt(100000, 999999).toString();
  
      const nuevoUsuario = new this.userModel({
        name: createUserDto.name,
        email: createUserDto.email,
        password: contraseñaEncriptada,
        verificationCode: codigoVerificacion,
        verificationCodeExpires: new Date(Date.now() + 5 * 60 * 1000),
      });
  
      const guardarUsuario = await nuevoUsuario.save();
      await this.sendVerificationEmail(createUserDto.email, codigoVerificacion);
      return this.mapToUserInterface(guardarUsuario);
    }
  
    async findAll(): Promise<User[]> {
      const usuarios = await this.userModel.find().lean().exec();
      return usuarios.map((user) => this.mapToUserInterface(user));
    }
  
    async findOne(id: string): Promise<User> {
      const usuario = await this.userModel.findById(id).lean().exec();
      if (!usuario) throw new NotFoundException('Usuario no encontrado');
      return this.mapToUserInterface(usuario);
    }
  
    async findByEmail(email: string): Promise<User> {
      const usuario = await this.userModel.findOne({ email }).lean().exec();
      if (!usuario) throw new NotFoundException('Usuario no encontrado');
      return this.mapToUserInterface(usuario);
    }
  
    async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
      if (updateUserDto.email) {
        const existingUser = await this.userModel.findOne({
          email: updateUserDto.email,
        });
        if (existingUser && existingUser.id !== id) {
          throw new ConflictException('Email ya en uso');
        }
      }
  
      const usuarioActualizado = await this.userModel.findByIdAndUpdate(id, updateUserDto, { new: true }).lean().exec();
        
      if (!usuarioActualizado) throw new NotFoundException('Usuario no encontrado');
      return this.mapToUserInterface(usuarioActualizado);
    }
  
    async remove(id: string): Promise<void> {
      const result = await this.userModel.findByIdAndDelete(id).exec();
      if (!result) throw new NotFoundException('Usuario no encontrado');
    }
  
    async verifyUser(id: string): Promise<User> {
      const usuario = await this.userModel.findByIdAndUpdate(id, { isVerified: true }, { new: true }).lean().exec();
        
      if (!usuario) throw new NotFoundException('Usuario no encontrado');
      return this.mapToUserInterface(usuario);
    }
  
    async login(
      loginDto: LoginDto,
    ): Promise<{ accessToken: string; refreshToken: string; user: User }> {
      const usuario = await this.userModel.findOne({ email: loginDto.email });
      if (!usuario) throw new UnauthorizedException('Credenciales inválidas');
  
      const contraseñaValida = await bcrypt.compare(
        loginDto.password,
        usuario.password,
      );
  
      const accessToken = this.jwtService.sign({
        sub: usuario.id,
        email: usuario.email,
      });
  
      const refreshToken = this.jwtService.sign(
        { sub: usuario.id },
        { expiresIn: '7d' },
      );
  
      return {
        accessToken, refreshToken, user: this.mapToUserInterface(usuario),
      };
    }
  
    async refreshToken(
      refreshToken: string,
    ): Promise<{ accessToken: string; refreshToken: string }> {
      try {
        const payload = this.jwtService.verify(refreshToken);
        const usuario = await this.findOne(payload.sub);
  
        const newAccessToken = this.jwtService.sign({
          sub: usuario.id,
          email: usuario.email,
        });
  
        const newRefreshToken = this.jwtService.sign(
          { sub: usuario.id },
          { expiresIn: '7d' },
        );
  
        return {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        };
      } catch (error) {
        throw new UnauthorizedException('Token de refresco inválido o expirado');
      }
    }
  
    async changePassword(id: string, changePasswordDto: ChangePasswordDto): Promise<void> {
      const usuario = await this.userModel.findById(id);
      if (!usuario) throw new NotFoundException('Usuario no encontrado');
  
      const contraseñaCorrecta = await bcrypt.compare(changePasswordDto.currentPassword, usuario.password,
      );
  
      if (!contraseñaCorrecta) {
        throw new UnauthorizedException('Contraseña actual incorrecta');
      }
  
      usuario.password = await bcrypt.hash(changePasswordDto.newPassword, 10);
      await usuario.save();
    }
  
    private mapToUserInterface(userDoc: any): User {
      return {id: userDoc._id ? userDoc._id.toString() : userDoc.id,
        name: userDoc.name,
        email: userDoc.email,
        isVerified: userDoc.isVerified,
        role: userDoc.role,
        refreshToken: userDoc.refreshToken,
        createdAt: userDoc.createdAt,
        updatedAt: userDoc.updatedAt,
      };
    }
  
    private async sendVerificationEmail(
      email: string,
      verificationCode: string,
    ): Promise<void> {
      await this.transporter.sendMail({
        from: `"${process.env.EMAIL_NAME}" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Verifica tu cuenta',
        html: `Tu código de verificación es: <b>${verificationCode}</b>`,
      });
    }
  }