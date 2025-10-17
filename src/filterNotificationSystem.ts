import express, { Request, Response, NextFunction } from 'express';
import { createConnection, Entity, PrimaryGeneratedColumn, Column, ManyToOne, BaseEntity, getRepository, Connection, Repository } from 'typeorm';
import { createLogger, format, transports, Logger } from 'winston';
import nodemailer, { Transporter } from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// ==============================
// TypeORM Entities
// ==============================

@Entity('users')
class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ unique: true })
  email!: string;

  @Column()
  name!: string;

  @Column()
  role!: string; // e.g., 'COMPLIANCE_OFFICER', 'ADMIN'

  @Column({ default: true })
  isActive!: boolean;

  @Column({ default: false })
  isEmailVerified!: boolean;
}

@Entity('notification_preferences')
class NotificationPreference extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @ManyToOne(() => User)
  user!: User;

  @Column()
  notificationType!: string; // e.g., 'STATIC_FILTER_CHANGE'

  @Column({ default: true })
  subscribed!: boolean;
}

@Entity('static_filters')
class StaticFilter extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column()
  name!: string;

  @Column()
  tableName!: string;

  @Column()
  columnName!: string;

  @Column()
  createdBy!: string; // user id

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt!: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updatedAt!: Date;
}

@Entity('audit_logs')
class AuditLog extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column()
  action!: string; // e.g., 'FILTER_MODIFIED', 'FILTER_REMOVED', 'NOTIFICATION_SENT', 'NOTIFICATION_FAILED'

  @Column({ type: 'jsonb', nullable: true })
  metadata!: any;

  @Column()
  performedBy!: string; // user id

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  timestamp!: Date;

  @Column({ nullable: true })
  status!: string; // e.g., 'SUCCESS', 'FAILED'
}

// ==============================
// Logger Setup (Winston)
// ==============================

const logger: Logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.splat(),
    format.json()
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'logs/filter_notification_system.log' })
  ]
});

// ==============================
// Nodemailer Setup
// ==============================

const mailTransporter: Transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ==============================
// Notification Service
// ==============================

type NotificationPayload = {
  filterName: string;
  tableName: string;
  columnName: string;
  action: 'MODIFIED' | 'REMOVED';
  performedBy: string;
  performedByName: string;
  timestamp: string;
};

class NotificationService {
  private transporter: Transporter;
  private logger: Logger;
  private maxRetries: number = 3;

  constructor(transporter: Transporter, logger: Logger) {
    this.transporter = transporter;
    this.logger = logger;
  }

  /**
   * Send notification to a compliance officer.
   * Retries up to maxRetries on failure.
   */
  async sendNotification(
    recipient: User,
    payload: NotificationPayload
  ): Promise<{ success: boolean; error?: string }> {
    let attempt = 0;
    let lastError: string | undefined = undefined;

    const mailOptions = {
      from: process.env.NOTIFICATION_FROM_EMAIL || 'no-reply@compliance.local',
      to: recipient.email,
      subject: `[Compliance Alert] Static Filter ${payload.action}: ${payload.filterName}`,
      text: this.generateNotificationText(payload)
    };

    while (attempt < this.maxRetries) {
      try {
        await this.transporter.sendMail(mailOptions);
        this.logger.info(
          `Notification sent to ${recipient.email} for filter ${payload.filterName} (${payload.action})`
        );
        return { success: true };
      } catch (err: any) {
        lastError = err.message || 'Unknown error';
        this.logger.error(
          `Failed to send notification to ${recipient.email} (attempt ${attempt + 1}): ${lastError}`
        );
        attempt++;
        await this.sleep(1000 * attempt); // Exponential backoff
      }
    }
    return { success: false, error: lastError };
  }

  /**
   * Generate notification text (no sensitive data).
   */
  generateNotificationText(payload: NotificationPayload): string {
    return (
      `A static filter has been ${payload.action.toLowerCase()}.\n\n` +
      `Filter Name: ${payload.filterName}\n` +
      `Table: ${payload.tableName}\n` +
      `Column: ${payload.columnName}\n` +
      `Action: ${payload.action}\n` +
      `Performed By: ${payload.performedByName}\n` +
      `Timestamp: ${payload.timestamp}\n\n` +
      `If you have questions, please contact your system administrator.`
    );
  }

  private sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// ==============================
// Compliance Officer Lookup Service
// ==============================

class ComplianceOfficerService {
  private userRepo: Repository<User>;
  private prefRepo: Repository<NotificationPreference>;

  constructor(connection: Connection) {
    this.userRepo = connection.getRepository(User);
    this.prefRepo = connection.getRepository(NotificationPreference);
  }

  /**
   * Get all active, authenticated, subscribed Compliance Officers.
   */
  async getSubscribedOfficers(): Promise<User[]> {
    const officers = await this.userRepo
      .createQueryBuilder('user')
      .leftJoinAndSelect(
        'notification_preferences',
        'pref',
        'pref.userId = user.id AND pref.notificationType = :type',
        { type: 'STATIC_FILTER_CHANGE' }
      )
      .where('user.role = :role', { role: 'COMPLIANCE_OFFICER' })
      .andWhere('user.isActive = true')
      .andWhere('user.isEmailVerified = true')
      .andWhere('(pref.subscribed = true OR pref.subscribed IS NULL)')
      .getMany();

    return officers;
  }
}

// ==============================
// Audit Logging Service
// ==============================

class AuditLogger {
  private auditRepo: Repository<AuditLog>;
  private logger: Logger;

  constructor(connection: Connection, logger: Logger) {
    this.auditRepo = connection.getRepository(AuditLog);
    this.logger = logger;
  }

  /**
   * Log an auditable action.
   */
  async log(
    action: string,
    metadata: any,
    performedBy: string,
    status: string
  ): Promise<void> {
    try {
      const log = this.auditRepo.create({
        action,
        metadata,
        performedBy,
        status
      });
      await this.auditRepo.save(log);
      this.logger.info(
        `Audit log: action=${action}, performedBy=${performedBy}, status=${status}`
      );
    } catch (err: any) {
      this.logger.error(
        `Failed to write audit log: action=${action}, performedBy=${performedBy}, error=${err.message}`
      );
    }
  }
}

// ==============================
// Filter Change Detection & Controller
// ==============================

class FilterController {
  private filterRepo: Repository<StaticFilter>;
  private userRepo: Repository<User>;
  private notificationService: NotificationService;
  private complianceOfficerService: ComplianceOfficerService;
  private auditLogger: AuditLogger;

  constructor(
    connection: Connection,
    notificationService: NotificationService,
    complianceOfficerService: ComplianceOfficerService,
    auditLogger: AuditLogger
  ) {
    this.filterRepo = connection.getRepository(StaticFilter);
    this.userRepo = connection.getRepository(User);
    this.notificationService = notificationService;
    this.complianceOfficerService = complianceOfficerService;
    this.auditLogger = auditLogger;
  }

  /**
   * Modify a static filter (demo: only name/column/table can be changed).
   */
  async modifyFilter(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { filterId } = req.params;
      const { name, tableName, columnName } = req.body;
      const userId = req.header('x-user-id'); // Authenticated user id

      if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      const user = await this.userRepo.findOne({ where: { id: userId } });
      if (!user || !user.isActive) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      const filter = await this.filterRepo.findOne({ where: { id: filterId } });
      if (!filter) {
        res.status(404).json({ error: 'Filter not found' });
        return;
      }

      // Only allow admins to modify
      if (user.role !== 'ADMIN') {
        res.status(403).json({ error: 'Insufficient permissions' });
        return;
      }

      // Update filter (no sensitive data)
      filter.name = name || filter.name;
      filter.tableName = tableName || filter.tableName;
      filter.columnName = columnName || filter.columnName;
      filter.updatedAt = new Date();
      await this.filterRepo.save(filter);

      // Audit log for filter modification
      await this.auditLogger.log(
        'FILTER_MODIFIED',
        {
          filterId: filter.id,
          name: filter.name,
          tableName: filter.tableName,
          columnName: filter.columnName
        },
        user.id,
        'SUCCESS'
      );

      // Notify compliance officers
      await this.notifyComplianceOfficers(
        filter,
        'MODIFIED',
        user
      );

      res.status(200).json({ message: 'Filter modified successfully' });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Remove a static filter.
   */
  async removeFilter(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { filterId } = req.params;
      const userId = req.header('x-user-id'); // Authenticated user id

      if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      const user = await this.userRepo.findOne({ where: { id: userId } });
      if (!user || !user.isActive) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      const filter = await this.filterRepo.findOne({ where: { id: filterId } });
      if (!filter) {
        res.status(404).json({ error: 'Filter not found' });
        return;
      }

      // Only allow admins to remove
      if (user.role !== 'ADMIN') {
        res.status(403).json({ error: 'Insufficient permissions' });
        return;
      }

      // Remove filter
      await this.filterRepo.remove(filter);

      // Audit log for filter removal
      await this.auditLogger.log(
        'FILTER_REMOVED',
        {
          filterId: filter.id,
          name: filter.name,
          tableName: filter.tableName,
          columnName: filter.columnName
        },
        user.id,
        'SUCCESS'
      );

      // Notify compliance officers
      await this.notifyComplianceOfficers(
        filter,
        'REMOVED',
        user
      );

      res.status(200).json({ message: 'Filter removed successfully' });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Notify all subscribed compliance officers about a filter change.
   */
  private async notifyComplianceOfficers(
    filter: StaticFilter,
    action: 'MODIFIED' | 'REMOVED',
    performedBy: User
  ): Promise<void> {
    const officers = await this.complianceOfficerService.getSubscribedOfficers();

    const payload: NotificationPayload = {
      filterName: filter.name,
      tableName: filter.tableName,
      columnName: filter.columnName,
      action,
      performedBy: performedBy.id,
      performedByName: performedBy.name,
      timestamp: new Date().toISOString()
    };

    for (const officer of officers) {
      try {
        const result = await this.notificationService.sendNotification(
          officer,
          payload
        );
        if (result.success) {
          await this.auditLogger.log(
            'NOTIFICATION_SENT',
            {
              recipient: officer.email,
              filterId: filter.id,
              action,
              notificationType: 'STATIC_FILTER_CHANGE'
            },
            performedBy.id,
            'SUCCESS'
          );
        } else {
          await this.auditLogger.log(
            'NOTIFICATION_FAILED',
            {
              recipient: officer.email,
              filterId: filter.id,
              action,
              notificationType: 'STATIC_FILTER_CHANGE',
              error: result.error
            },
            performedBy.id,
            'FAILED'
          );
        }
      } catch (err: any) {
        logger.error(
          `Unexpected error during notification delivery to ${officer.email}: ${err.message}`
        );
        await this.auditLogger.log(
          'NOTIFICATION_FAILED',
          {
            recipient: officer.email,
            filterId: filter.id,
            action,
            notificationType: 'STATIC_FILTER_CHANGE',
            error: err.message
          },
          performedBy.id,
          'FAILED'
        );
      }
    }
  }
}

// ==============================
// Express App Setup
// ==============================

const app = express();
app.use(express.json());

// Database connection and service initialization
let connection: Connection;
let notificationService: NotificationService;
let complianceOfficerService: ComplianceOfficerService;
let auditLogger: AuditLogger;
let filterController: FilterController;

// Middleware for error handling
function errorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) {
  logger.error(`Unhandled error: ${err.message}`, { stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
}

// API Endpoints

/**
 * PATCH /filters/:filterId
 * Modify a static filter (admin only)
 */
app.patch(
  '/filters/:filterId',
  async (req: Request, res: Response, next: NextFunction) => {
    await filterController.modifyFilter(req, res, next);
  }
);

/**
 * DELETE /filters/:filterId
 * Remove a static filter (admin only)
 */
app.delete(
  '/filters/:filterId',
  async (req: Request, res: Response, next: NextFunction) => {
    await filterController.removeFilter(req, res, next);
  }
);

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'ok' });
});

// Error handler
app.use(errorHandler);

// ==============================
// Bootstrap
// ==============================

async function bootstrap() {
  try {
    connection = await createConnection({
      type: 'postgres',
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT) || 5432,
      username: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      entities: [User, NotificationPreference, StaticFilter, AuditLog],
      synchronize: false, // Use migrations in production!
      logging: false
    });

    notificationService = new NotificationService(mailTransporter, logger);
    complianceOfficerService = new ComplianceOfficerService(connection);
    auditLogger = new AuditLogger(connection, logger);
    filterController = new FilterController(
      connection,
      notificationService,
      complianceOfficerService,
      auditLogger
    );

    const port = process.env.PORT || 3000;
    app.listen(port, () => {
      logger.info(`Static Filter Notification System running on port ${port}`);
    });
  } catch (err: any) {
    logger.error(`Failed to bootstrap application: ${err.message}`);
    process.exit(1);
  }
}

bootstrap();

// ==============================
// Exports
// ==============================

export {
  app,
  User,
  NotificationPreference,
  StaticFilter,
  AuditLog,
  NotificationService,
  ComplianceOfficerService,
  AuditLogger,
  FilterController
};