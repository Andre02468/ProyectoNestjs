import { Injectable, UnauthorizedException } from '@nestjs/common';
import { User, UserServiceInterface } from './interfaces/user.interface';
import { CreateUserDto, UpdateUserDto, LoginDto, ChangePasswordDto } from './dto/user.dto';
import * as nodemailer from 'nodemailer';
import { UserDocument, UserModel } from './schemas/user.schema'
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { randomInt } from 'crypto';

@Injectable()

export class UserService implements UserServiceInterface {
    private sendEmail = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.PORT,
        secure: false,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    constructor( 
        @InjectModel(UserModel.name) private userModel: Model<UserDocument>,
        private jwtService: JwtService,
    ) {}

    async create(createUserDto: CreateUserDto): Promise<User> {
      const usuarioExistente = await this.userModel.findOne({
       email: createUserDto.email
      }); 

      if (usuarioExistente){
       throw new Error ('el email ya se ecuentra registrado');
      }
      const contraseñaEncriptada = await bcrypt.hash(createUserDto.password, 8);
      const codigoVerificacion = randomInt(100000, 999999).toString();
      console.log(createUserDto);
      const nuevoUsuario = new this.userModel({
       name: createUserDto.name, 
       email: createUserDto.email,
       password: contraseñaEncriptada,
       verificationCode: codigoVerificacion,
       verificationCodeExpires: Date.now() + 5*60*1000,
      });
      const guardarUsuario = await nuevoUsuario.save();
      await this.sendVerificationEmail(createUserDto.email,codigoVerificacion);
      return this.mapToUserInterface(guardarUsuario);
   }

    async findAll(): Promise<User[]> {
        const usuarios = await this.userModel.find().lean().exec();
        return usuarios.map((user) =>this.mapToUserInterface(user));
    }
    async findOne(id: string): Promise<User> {
        const usuario = await this.userModel.findById(id).lean().exec();
        return this.mapToUserInterface(usuario); 
    }
    async findByEmail(email: string): Promise<User> {
        const usuario = await this.userModel.findOne({email: email}).lean().exec();
        return this.mapToUserInterface(usuario); 
    }
    async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
        const usuarioActualizado = this.userModel.findByIdAndUpdate(id, updateUserDto, {new: true}).lean().exec();
        return this.mapToUserInterface(usuarioActualizado);
    }
    async remove(id: string): Promise<void> {
        const usuarioActualizado = this.userModel.findByIdAndDelete(id).exec();
    }
    async verifyUser(id: string, verificationCode: string): Promise<User>{
      const user = await this.userModel.findById(id);
      if (!user) throw new Error('Usuario no encontrado');
  
      if (user.verificationCode !== verificationCode) {
        throw new Error('Código de verificación incorrecto'); 
      }
  
      const updatedUser = await this.userModel.findByIdAndUpdate(
        id,
        { isVerified: true },
        { new: true},
      );
      return this.mapToUserInterface(updatedUser);
    }
    async login(loginDto: LoginDto,): Promise<{ accessToken: string; refreshToken: string; user: User }> {
        const usuario = await this.userModel.findOne({ email: loginDto.email });
        const contraseñaEncriptada = await bcrypt.compare(
          loginDto.password,
          usuario.password,
        );
        
        if (!contraseñaEncriptada) {
          throw new UnauthorizedException('Credenciales inválidas');
        }
        
        if (!usuario.isVerified) {
          throw new UnauthorizedException('Cuenta no verificada');
        }
    
        const accessToken = this.jwtService.sign({
          sub: usuario.id,
          email: usuario.email,
        });
        
        const refreshToken = this.jwtService.sign(
          { sub: usuario.id },
          { expiresIn: '7d' },
        );
    
        return {accessToken, refreshToken, user: this.mapToUserInterface(usuario)};

      }

    async refreshToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
        try {
        const tokenVerificado = this.jwtService.verify(refreshToken);
        const usuario = await this.findOne(tokenVerificado.sub);

        const newAccessToken = this.jwtService.sign({
            sub: usuario.id,
            email: usuario.email,
        });
        
        const newRefreshToken = this.jwtService.sign(
            { sub: usuario.id },
            { expiresIn: '7d' },
        );

        return {accessToken: newAccessToken, refreshToken: newRefreshToken};
        } 
        catch (error) {
            throw new UnauthorizedException('token de refresco invalido o ya expiro');
        }
    }
    async changePassword(id: string, changePasswordDto: ChangePasswordDto): Promise<void> {
       const usuario = await this.userModel.findById(id);
       const contraseñaCorrecta = await bcrypt.compare(changePasswordDto.currentPassword, usuario.password);
       usuario.password = await bcrypt.hash(changePasswordDto.newPassword, 8);
       await usuario.save();
    }

    private mapToUserInterface(UserDoc: any): User {
        return {
          id: UserDoc._id ? UserDoc._id.toString() : UserDoc.id,
          name: UserDoc.name,
          email: UserDoc.email,
          isVerified: UserDoc.isVerified,
          role: UserDoc.role,
          refreshToken: UserDoc.refreshToken,
          createdAt: UserDoc.createdAt,
          updatedAt: UserDoc.updatedAt,
        };
      }

    private async sendVerificationEmail(email: string, verificationCode: string) {
        await this.sendEmail.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Verifica tu cuenta',
          html:`tu código de verificación es: <b>${verificationCode}<b>`,
        });
      }
}