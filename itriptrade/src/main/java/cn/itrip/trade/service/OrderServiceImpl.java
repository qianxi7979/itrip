package cn.itrip.trade.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Service;

import cn.itrip.beans.pojo.ItripHotelOrder;
import cn.itrip.common.EmptyUtils;
import cn.itrip.dao.itripHotelOrder.ItripHotelOrderMapper;

@Service("orderService")
public class OrderServiceImpl implements OrderService {

	private Logger logger=Logger.getLogger(OrderServiceImpl.class);
	@Resource
	private ItripHotelOrderMapper itripHotelOrderMapper;

	@Override
	public ItripHotelOrder loadItripHotelOrder(String orderNo) throws Exception {
		// TODO Auto-generated method stub
		logger.debug("加载订单："+orderNo);
		Map<String, Object> param=new HashMap();
		param.put("orderNo", orderNo);
		List<ItripHotelOrder> orders=itripHotelOrderMapper.getItripHotelOrderListByMap(param);
		if(orders.size()==1){
			return orders.get(0);
		}else
			return null;
	}

	@Override
	public void paySuccess(String orderNo, int payType,String tradeNo) throws Exception {
		// TODO Auto-generated method stub
		logger.debug("订单支付成功："+orderNo);
		ItripHotelOrder itripHotelOrder=this.loadItripHotelOrder(orderNo);
		itripHotelOrder.setOrderStatus(2);//支付成功
		itripHotelOrder.setPayType(payType);
		itripHotelOrder.setTradeNo(tradeNo);//交易号（如支付宝交易号）
		itripHotelOrderMapper.updateItripHotelOrder(itripHotelOrder);
	}

	@Override
	public void payFailed(String orderNo, int payType,String tradeNo) throws Exception {
		// TODO Auto-generated method stub
		logger.debug("订单支付失败："+orderNo);
		ItripHotelOrder itripHotelOrder=this.loadItripHotelOrder(orderNo);
		itripHotelOrder.setOrderStatus(1);//支付状态：已取消
		itripHotelOrder.setPayType(payType);
		itripHotelOrder.setTradeNo(tradeNo);//交易号（如支付宝交易号）
		itripHotelOrderMapper.updateItripHotelOrder(itripHotelOrder);
	}

	@Override
	public boolean processed(String orderNo) throws Exception {
		// TODO Auto-generated method stub
		ItripHotelOrder itripHotelOrder=this.loadItripHotelOrder(orderNo);
		return itripHotelOrder.getOrderStatus().equals(2)&&
				!EmptyUtils.isEmpty(itripHotelOrder.getTradeNo());
	}

}
