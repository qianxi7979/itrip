package cn.itrip.controller;

import cn.itrip.beans.dtos.Dto;
import cn.itrip.beans.pojo.*;
import cn.itrip.beans.vo.order.ItripAddHotelOrderVO;
import cn.itrip.beans.vo.order.ItripModifyHotelOrderVO;
import cn.itrip.beans.vo.order.ItripSearchOrderVO;
import cn.itrip.beans.vo.order.PreAddOrderVO;
import cn.itrip.beans.vo.store.StoreVO;
import cn.itrip.common.*;
import cn.itrip.service.itripHotel.ItripHotelService;
import cn.itrip.service.itripHotelOrder.ItripHotelOrderService;
import cn.itrip.service.itripHotelRoom.ItripHotelRoomService;
import cn.itrip.service.itripHotelTempStore.ItripHotelTempStoreService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.log4j.Logger;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by donghai on 2017/5/15.
 * <p/>
 * <p/>
 * 注：错误码（100501 ——100600）
 */
@Controller
@Api(value = "API", basePath = "/http://api.itrap.com/api")
@RequestMapping(value = "/api/hotelorder")
public class HotelOrderController {

    private Logger logger = Logger.getLogger(HotelController.class);

    @Resource
    private ValidationToken validationToken;

    @Resource
    private ItripHotelService hotelService;

    @Resource
    private ItripHotelRoomService roomService;

    @Resource
    private ItripHotelTempStoreService tempStoreService;

    @Resource
    private SystemConfig systemConfig;

    @Resource
    private ItripHotelTempStoreService itripHotelTempStoreService;

    @Resource
    private ItripHotelOrderService itripHotelOrderService;


    @ApiOperation(value = "根据个人订单列表，并分页显示", httpMethod = "POST",
            protocols = "HTTP",produces = "application/json",
            response = Dto.class,notes = "根据条件查询个人订单列表，并分页显示"+
            "<p>订单类型(orderType)（-1：全部订单 0:旅游订单 1:酒店订单 2：机票订单）：</p>" +
            "<p>订单状态(orderStatus)（0：待支付 1:已取消 2:支付成功 3:已消费）：</p>" +
            "<p>对于页面tab条件：</p>" +
            "<p>全部订单（orderStatus：-1）</p>" +
            "<p>未出行（orderStatus：2）</p>" +
            "<p>待付款（orderStatus：0）</p>" +
            "<p>待评论（orderStatus：3）</p>" +
            "<p>已取消（orderStatus：1）</p>" +
            "<p>成功：success = ‘true’ | 失败：success = ‘false’ 并返回错误码，如下：</p>" +
            "<p>错误码：</p>"+
            "<p>100501 : 请传递参数：orderType </p>"+
            "<p>100502 : 请传递参数：orderStatus </p>"+
            "<p>100503 : 获取个人订单列表错误 </p>"+
            "<p>100504 : token失效，请重登录 </p>")
    @RequestMapping(value = "/getpersonalorderlist",method=RequestMethod.POST,produces = "application/json")
    @ResponseBody
    public Dto<Object> getPersonalOrderList(@RequestBody ItripSearchOrderVO itripSearchOrderVO,
                                            HttpServletRequest request){
        logger.debug("orderType : " + itripSearchOrderVO.getOrderType());
        logger.debug("orderStatus : " + itripSearchOrderVO.getOrderStatus());
        Integer orderType = itripSearchOrderVO.getOrderType();
        Integer orderStatus = itripSearchOrderVO.getOrderStatus();
        Dto<Object> dto = null;
        String tokenString  = request.getHeader("token");
        logger.debug("token name is from header : " + tokenString);
        ItripUser currentUser = validationToken.getCurrentUser(tokenString);
        if(null != currentUser){
            if(orderType == null){
                return DtoUtil.returnFail("请传递参数：orderType","100501");
            }
            if(orderStatus == null){
                return DtoUtil.returnFail("请传递参数：orderStatus","100502");
            }

            Map<String,Object> param=new HashMap<>();
            param.put("orderType",orderType == -1?null:orderType);
            param.put("orderStatus",orderStatus == -1?null:orderStatus);
            param.put("userId",currentUser.getId());
            param.put("orderNo",itripSearchOrderVO.getOrderNo());
            param.put("linkUserName",itripSearchOrderVO.getLinkUserName());
            param.put("startDate",itripSearchOrderVO.getStartDate());
            param.put("endDate",itripSearchOrderVO.getEndDate());
            try{
                Page page = itripHotelOrderService.queryOrderPageByMap(param,
                        itripSearchOrderVO.getPageNo(),
                        itripSearchOrderVO.getPageSize());
                dto = DtoUtil.returnSuccess("获取个人订单列表成功",page);
            }catch (Exception e){
                e.printStackTrace();
                dto = DtoUtil.returnFail("获取个人订单列表错误","100503");
            }

        }else{
            dto = DtoUtil.returnFail("token失效，请重登录","100504");
        }
        return dto;
    }

    @ApiOperation(value = "生成订单", httpMethod = "POST",
            protocols = "HTTP", produces = "application/json",
            response = Dto.class, notes = "生成订单" +
            "<p>成功：success = ‘true’ | 失败：success = ‘false’ 并返回错误码，如下：</p>" +
            "<p>错误码：</p>" +
            "<p>100503 : 生成订单失败 </p>" +
            "<p>100504 : 不能提交空，请填写订单信息 </p>" +
            "<p>100505 : token失效，请重登录 </p>" +
            "<p>100506 : 库存不足</p>")
    @RequestMapping(value = "/addhotelorder", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    public Dto<Object> addHotelOrder(@RequestBody ItripAddHotelOrderVO itripAddHotelOrderVO, HttpServletRequest request) {
        //ItripComment

        Dto<Object> dto = new Dto<Object>();
        String tokenString = request.getHeader("token");
        logger.debug("token name is from header : " + tokenString);
        ItripUser currentUser = validationToken.getCurrentUser(tokenString);
        Map<String, Object> validateStoreMap = new HashMap<String, Object>();
        validateStoreMap.put("startTime", itripAddHotelOrderVO.getCheckInDate());
        validateStoreMap.put("endTime", itripAddHotelOrderVO.getCheckOutDate());
        validateStoreMap.put("hotelId", itripAddHotelOrderVO.getHotelId());
        validateStoreMap.put("roomId", itripAddHotelOrderVO.getRoomId());
        validateStoreMap.put("count", itripAddHotelOrderVO.getCount());
        Boolean flag = false;
        try {
            flag = itripHotelTempStoreService.validateRoomStore(validateStoreMap);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (flag) {
            if (null != currentUser && null != itripAddHotelOrderVO) {
                //计算订单的预定天数
                Integer days = DateUtil.getBetweenDates(
                        itripAddHotelOrderVO.getCheckInDate(), itripAddHotelOrderVO.getCheckOutDate()
                ).size();
                ItripHotelOrder itripHotelOrder = new ItripHotelOrder();
                itripHotelOrder.setUserId(currentUser.getId());
                itripHotelOrder.setOrderType(itripAddHotelOrderVO.getOrderType());
                itripHotelOrder.setHotelId(itripAddHotelOrderVO.getHotelId());
                itripHotelOrder.setHotelName(itripAddHotelOrderVO.getHotelName());
                itripHotelOrder.setRoomId(itripAddHotelOrderVO.getRoomId());
                itripHotelOrder.setCount(itripAddHotelOrderVO.getCount());
                itripHotelOrder.setCheckInDate(itripAddHotelOrderVO.getCheckInDate());
                itripHotelOrder.setCheckOutDate(itripAddHotelOrderVO.getCheckOutDate());
                itripHotelOrder.setNoticePhone(itripAddHotelOrderVO.getNoticePhone());
                itripHotelOrder.setNoticeEmail(itripAddHotelOrderVO.getNoticeEmail());
                itripHotelOrder.setSpecialRequirement(itripAddHotelOrderVO.getSpecialRequirement());
                itripHotelOrder.setIsNeedInvoice(itripAddHotelOrderVO.getIsNeedInvoice());
                itripHotelOrder.setInvoiceHead(itripAddHotelOrderVO.getInvoiceHead());
                itripHotelOrder.setInvoiceType(itripAddHotelOrderVO.getInvoiceType());
                itripHotelOrder.setCreatedBy(currentUser.getId());
                itripHotelOrder.setLinkUserName(itripAddHotelOrderVO.getLinkUserName());
                itripHotelOrder.setBookingDays(days);
                //支付之前生成的订单的初始状态为未支付
                itripHotelOrder.setOrderStatus(0);
                try {
                    //生成MD5
                    StringBuilder md5String = new StringBuilder();
                    md5String.append(itripHotelOrder.getHotelId());
                    md5String.append(itripHotelOrder.getRoomId());
                    md5String.append(System.currentTimeMillis());
                    md5String.append(Math.random() * 1000000);
                    String md5 = MD5.getMd5(md5String.toString(), 6);

                    //生成订单编号
                    StringBuilder orderNo = new StringBuilder();
                    orderNo.append(systemConfig.getMachineCode());
                    orderNo.append(DateUtil.format(new Date(), "yyyyMMddHHmmss"));
                    orderNo.append(md5);
                    itripHotelOrder.setOrderNo(orderNo.toString());
                    //计算订单的总金额
                    itripHotelOrder.setPayAmount(itripHotelOrderService.getOrderPayAmount(days, itripAddHotelOrderVO.getRoomId()));
                    itripHotelOrderService.addItripHotelOrder(itripHotelOrder);
                    dto = DtoUtil.returnSuccess("生成订单成功");
                } catch (Exception e) {
                    e.printStackTrace();
                    dto = DtoUtil.returnFail("生成订单失败", "100503");
                }
            } else if (null != currentUser && null == itripAddHotelOrderVO) {
                dto = DtoUtil.returnFail("不能提交空，请填写订单信息", "100504");
            } else {
                dto = DtoUtil.returnFail("token失效，请重登录", "100505");
            }
        } else {
            dto = DtoUtil.returnFail("库存不足", "100506");
        }
        return dto;
    }

    @ApiOperation(value = "生成订单前,获取预订信息", httpMethod = "POST",
            protocols = "HTTP", produces = "application/json",
            response = Dto.class, notes = "生成订单前,获取预订信息" +
            "<p>成功：success = ‘true’ | 失败：success = ‘false’ 并返回错误码，如下：</p>" +
            "<p>错误码：</p>" +
            "<p>100506 : hotelId不能为空,roomId不能为空,暂时无房 </p>" +
            "<p>100507 : 系统异常</p>")
    @RequestMapping(value = "/getpreorderinfo", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    public Dto<PreAddOrderVO> getPreOrderInfo(@RequestBody PreAddOrderVO preAddOrderVO, HttpServletRequest request) {
        String tokenString = request.getHeader("token");
        ItripUser currentUser = validationToken.getCurrentUser(tokenString);
        ItripHotel hotel = null;
        ItripHotelRoom room = null;
        PreAddOrderVO preItripOrderVo = null;
        try {
            if(EmptyUtils.isEmpty(currentUser)){
                return DtoUtil.returnFail("用户登录超时","100506");
            }
            if (EmptyUtils.isEmpty(preAddOrderVO.getHotelId())) {
                return DtoUtil.returnFail("hotelId不能为空", "100506");
            } else if (EmptyUtils.isEmpty(preAddOrderVO.getRoomId())) {
                return DtoUtil.returnFail("roomId不能为空", "100506");
            } else {
                preItripOrderVo = new PreAddOrderVO();
                hotel = hotelService.getItripHotelById(preAddOrderVO.getHotelId());
                room = roomService.getItripHotelRoomById(preAddOrderVO.getRoomId());
                Map param = new HashMap();
                param.put("startTime", preAddOrderVO.getCheckInDate());
                param.put("endTime", preAddOrderVO.getCheckOutDate());
                param.put("roomId", preAddOrderVO.getRoomId());
                param.put("hotelId", preAddOrderVO.getHotelId());
                preItripOrderVo.setCheckInDate(preAddOrderVO.getCheckInDate());
                preItripOrderVo.setCheckOutDate(preAddOrderVO.getCheckOutDate());
                preItripOrderVo.setHotelName(hotel.getHotelName());
                preItripOrderVo.setRoomId(room.getId());
                preItripOrderVo.setPrice(room.getRoomPrice());
                preItripOrderVo.setHotelId(preAddOrderVO.getHotelId());
                List<StoreVO> storeVOList = tempStoreService.queryRoomStore(param);
                preItripOrderVo.setCount(1);
                if (EmptyUtils.isNotEmpty(storeVOList)) {
                    preItripOrderVo.setStore(storeVOList.get(0).getStore());
                } else {
                    return DtoUtil.returnFail("暂时无房", "100506");
                }
                return DtoUtil.returnSuccess("获取成功", preItripOrderVo);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail("系统异常", "100507");
        }
    }

    @ApiOperation(value = "修改订房日期验证是否有房", httpMethod = "POST",
            protocols = "HTTP", produces = "application/json",
            response = Dto.class, notes = "修改订房日期验证是否有房" +
            "<p>成功：success = ‘true’ | 失败：success = ‘false’ 并返回错误码，如下：</p>" +
            "<p>错误码：</p>" +
            "<p>100508 : hotelId不能为空,roomId不能为空, </p>" +
            "<p>100509 : 系统异常</p>")
    @RequestMapping(value = "/validateroomstore", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    public Dto<Map<String, Boolean>> validateRoomStore(@RequestBody PreAddOrderVO preAddOrderVO,HttpServletRequest request) {
        try {
            String tokenString = request.getHeader("token");
            ItripUser currentUser = validationToken.getCurrentUser(tokenString);
            if(EmptyUtils.isEmpty(currentUser)){
                return DtoUtil.returnFail("token失效，请重登录","100506");
            }
            if (EmptyUtils.isEmpty(preAddOrderVO.getHotelId())) {
                return DtoUtil.returnFail("hotelId不能为空", "100508");
            } else if (EmptyUtils.isEmpty(preAddOrderVO.getRoomId())) {
                return DtoUtil.returnFail("roomId不能为空", "100508");
            } else {
                Map param = new HashMap();
                param.put("startTime", preAddOrderVO.getCheckInDate());
                param.put("endTime", preAddOrderVO.getCheckOutDate());
                param.put("roomId", preAddOrderVO.getRoomId());
                param.put("hotelId", preAddOrderVO.getHotelId());
                param.put("count", preAddOrderVO.getCount());
                boolean flag = tempStoreService.validateRoomStore(param);
                Map<String, Boolean> map = new HashMap<String, Boolean>();
                map.put("flag", flag);
                return DtoUtil.returnSuccess("操作成功", map);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail("系统异常", "100509");
        }
    }

    @ApiOperation(value = "支付成功后查询订单信息", httpMethod = "POST",
            protocols = "HTTP", produces = "application/json",
            response = Dto.class, notes = "支付成功后查询订单信息" +
            "<p>成功：success = ‘true’ | 失败：success = ‘false’ 并返回错误码，如下：</p>" +
            "<p>错误码：</p>" +
            "<p>100510 : id不能为空 </p>" +
            "<p>100511 : 系统异常</p>")
    @RequestMapping(value = "/querysuccessorderinfo/{id}", method = RequestMethod.GET, produces = "application/json")
    public Dto<Map<String, Boolean>> querySuccessOrderInfo(@PathVariable Long id,HttpServletRequest request) {
        String tokenString = request.getHeader("token");
        ItripUser currentUser = validationToken.getCurrentUser(tokenString);
        if(EmptyUtils.isEmpty(currentUser)){
            return DtoUtil.returnFail("用户登录超时","100506");
        }
        if (EmptyUtils.isEmpty(id)) {
            return DtoUtil.returnFail("id不能为空", "100510");
        }
        try {
            ItripHotelOrder order = itripHotelOrderService.getItripHotelOrderById(id);
            ItripHotelRoom room = roomService.getItripHotelRoomById(order.getRoomId());
            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("id", order.getId());
            resultMap.put("orderNo", order.getOrderNo());
            resultMap.put("payType", order.getPayType());
            resultMap.put("payAmount", order.getPayAmount());
            resultMap.put("hotelName", order.getHotelName());
            resultMap.put("roomTitle", room.getRoomTitle());
            return DtoUtil.returnSuccess("获取数据成功", resultMap);
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail("id不能为空", "100511");
        }
    }
    /***
     * 10分钟执行一次 刷新订单的状态 不对外公布
     */
    @Scheduled(cron = "*/600 * * * * ?")
    public void flushOrderStatus() {
        try {
            boolean flag = itripHotelOrderService.flushOrderStatus();
            logger.info(flag?"刷取订单成功":"刷单失败");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @ApiOperation(value = "修改订单的支付方式和状态", httpMethod = "POST",
            protocols = "HTTP",produces = "application/json",
            response = Dto.class,notes = "修改订单的支付方式和状态"+
            "<p>成功：success = ‘true’ | 失败：success = ‘false’ 并返回错误码，如下：</p>" +
            "<p>错误码：</p>"+
            "<p>100510 : 修改订单失败, </p>"+
            "<p>100511 : 不能提交空，请填写订单信息, </p>"+
            "<p>100512 : token失效，请重新登录</p>")
    @RequestMapping(value = "/updateorderstatusandpaytype",method= RequestMethod.POST,produces = "application/json")
    @ResponseBody
    public Dto<Map<String,Boolean>> updateOrderStatusAndPayType(@RequestBody ItripModifyHotelOrderVO itripModifyHotelOrderVO, HttpServletRequest request) {
        String tokenString = request.getHeader("token");
        logger.debug("token name is from header : " + tokenString);
        ItripUser currentUser = validationToken.getCurrentUser(tokenString);
        if (null != currentUser && null != itripModifyHotelOrderVO) {
            ItripHotelOrder itripHotelOrder = new ItripHotelOrder();
            itripHotelOrder.setOrderStatus(itripModifyHotelOrderVO.getOrderStatus());
            itripHotelOrder.setPayType(itripModifyHotelOrderVO.getPayType());
            itripHotelOrder.setModifiedBy(currentUser.getId());
            itripHotelOrder.setModifyDate(new Date(System.currentTimeMillis()));
            try {
                itripHotelOrderService.itriptxModifyItripHotelOrder(itripHotelOrder);
            } catch (Exception e) {
                e.printStackTrace();
                return DtoUtil.returnFail("修改订单失败", "100510");
            }
            return DtoUtil.returnSuccess("修改订单成功");
        } else if (null != currentUser && null == itripModifyHotelOrderVO) {
            return DtoUtil.returnFail("不能提交空，请填写订单信息", "100511");
        } else {
            return DtoUtil.returnFail("token失效，请重新登录", "100512");
        }
    }
}
